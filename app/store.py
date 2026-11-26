"""State store with atomic file operations and portable locking.

State holds:
- owners: dict[asset_id, actor_id]
- contents: dict[asset_id, str]
- disabled: list[actor_id]
- revoked: list[actor_id]
- key_material: sensitive string, stored only in state file, never leaked
- key_version: int (monotonic key version for backup integrity)
- backup_metadata: dict
- last_tx_id: optional transaction id for crash recovery
"""

import contextlib
import json
import os
from pathlib import Path
import secrets
import tempfile
import time
from typing import Any, Dict, Optional

STALE_LOCK_SECONDS = 1.5
LOCK_ACQUIRE_TIMEOUT = 5.0


def _is_pid_alive(pid: int) -> bool:
    """Check if process with given PID is still running."""
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def get_state_dir() -> Path:
    """Resolve and create the state directory according to constraints."""
    env_dir = os.environ.get("TRACK4_STATE_DIR")
    if env_dir:
        path = Path(env_dir).resolve()
    else:
        path = Path(tempfile.gettempdir()).resolve()
    os.makedirs(path, exist_ok=True)
    return path


def get_state_file() -> Path:
    return get_state_dir() / "state.json"


def get_lock_file() -> Path:
    return get_state_dir() / "store.lock"


@contextlib.contextmanager
def file_lock(timeout: float = LOCK_ACQUIRE_TIMEOUT, stale_after: float = STALE_LOCK_SECONDS):
    """Portable file-based mutex using atomic O_CREAT | O_EXCL with stale recovery."""
    lock_path = get_lock_file()
    start_time = time.monotonic()
    fd = None

    while True:
        try:
            # Atomic file creation
            fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_RDWR)
            # Write PID and timestamp
            os.write(fd, f"{os.getpid()}:{time.time()}".encode("utf-8"))
            break
        except FileExistsError:
            # Check for dead PID or stale lock
            try:
                content = ""
                with open(str(lock_path), "r", encoding="utf-8") as lf:
                    content = lf.read().strip()
                if content and ":" in content:
                    pid_str, ts_str = content.split(":", 1)
                    pid = int(pid_str)
                    if not _is_pid_alive(pid):
                        try:
                            os.unlink(str(lock_path))
                            continue
                        except OSError:
                            pass
                mtime = os.path.getmtime(str(lock_path))
                if time.time() - mtime > stale_after:
                    try:
                        os.unlink(str(lock_path))
                        continue
                    except OSError:
                        pass
            except (OSError, ValueError):
                pass

            if time.monotonic() - start_time > timeout:
                raise TimeoutError(f"Could not acquire lock within {timeout}s")
            time.sleep(0.01)

    try:
        yield
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
            try:
                os.unlink(str(lock_path))
            except OSError:
                pass


def fsync_dir_if_supported(dir_path: Path) -> None:
    """fsync directory on POSIX systems where supported; no-op on Windows."""
    if hasattr(os, "O_DIRECTORY"):
        try:
            dir_fd = os.open(str(dir_path), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            pass


def load_state() -> Optional[Dict[str, Any]]:
    """Load state from state.json if it exists."""
    state_file = get_state_file()
    if not state_file.exists():
        return None
    try:
        with open(state_file, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def save_state(state: Dict[str, Any]) -> None:
    """Save state atomically using write-to-temp + fsync + os.replace."""
    state_dir = get_state_dir()
    state_file = get_state_file()
    temp_file = state_dir / f"state.json.tmp.{secrets.token_hex(8)}"

    encoded = json.dumps(state, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)

    with open(temp_file, "w", encoding="utf-8") as f:
        f.write(encoded)
        f.flush()
        os.fsync(f.fileno())

    # Single atomic replacement is the store update
    os.replace(temp_file, state_file)
    fsync_dir_if_supported(state_dir)


def init_state(owners: Dict[str, str], contents: Dict[str, str], disabled: list, key_material: str) -> Dict[str, Any]:
    """Initialize a fresh state dictionary."""
    state = {
        "owners": dict(owners),
        "contents": dict(contents),
        "disabled": list(disabled),
        "revoked": [],
        "key_material": key_material,
        "key_version": 1,
        "backup_metadata": {},
        "last_tx_id": None,
    }
    save_state(state)
    return state
