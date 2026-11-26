"""Atomic, cross-process persistent storage for the key management service."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import tempfile
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from .crypto import ML_KEM_SECRET_KEY_SIZE
from .exceptions import StorageIntegrityError, ValidationError
from .models import ALGORITHM, SCHEMA_VERSION, KeyRecord, RevocationRecord

if os.name == "nt":
    import msvcrt
else:
    import fcntl

_KEY_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")
_THREAD_LOCKS_GUARD = threading.Lock()
_THREAD_LOCKS: dict[Path, threading.RLock] = {}


def _get_thread_lock(lock_path: Path) -> threading.RLock:
    with _THREAD_LOCKS_GUARD:
        lock = _THREAD_LOCKS.get(lock_path)
        if lock is None:
            lock = threading.RLock()
            _THREAD_LOCKS[lock_path] = lock
        return lock


def resolve_state_dir(explicit_dir: str | Path | None = None) -> Path:
    """Resolve the external persistent state directory outside the repository.

    Uses ``explicit_dir`` if provided, otherwise ``TRACK4_STATE_DIR`` if set and
    non-empty, and otherwise falls back to an OS temporary directory.
    """
    if explicit_dir is not None:
        raw = str(explicit_dir).strip()
        if not raw:
            raise ValidationError("state_dir must not be empty.")
        return Path(raw).expanduser().resolve()

    env_dir = os.environ.get("TRACK4_STATE_DIR")
    if env_dir is not None and env_dir.strip():
        return Path(env_dir.strip()).expanduser().resolve()

    return Path(tempfile.gettempdir()).resolve() / "secure_pqc_prototype_state"


def validate_key_id_filename(key_id: str) -> None:
    """Ensure ``key_id`` is safe for use as a single-segment filename."""
    if not isinstance(key_id, str) or not _KEY_ID_PATTERN.fullmatch(key_id):
        raise ValidationError("key_id must be an alphanumeric/dash/underscore identifier.")


def atomic_write_bytes(
    target: Path,
    data: bytes,
    *,
    file_mode: int | None = None,
    dir_mode: int | None = None,
) -> None:
    """Atomically write ``data`` to ``target`` via temp file, flush, fsync, and os.replace."""
    target.parent.mkdir(parents=True, exist_ok=True)
    if dir_mode is not None:
        try:
            os.chmod(target.parent, dir_mode)
        except OSError:
            pass

    tmp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=target.parent,
            prefix=f".{target.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            tmp_path = Path(handle.name)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())

        if file_mode is not None:
            try:
                os.chmod(tmp_path, file_mode)
            except OSError:
                pass

        os.replace(tmp_path, target)
        tmp_path = None

        if os.name != "nt":
            try:
                dir_fd = os.open(target.parent, os.O_RDONLY)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
            except OSError:
                pass
    finally:
        if tmp_path is not None:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass


@contextmanager
def file_lock(lock_path: Path) -> Iterator[None]:
    """Acquire thread-level and OS-level cross-process exclusive locks on ``lock_path``."""
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    thread_lock = _get_thread_lock(lock_path)
    with thread_lock:
        with open(lock_path, "a+b") as lock_file:
            lock_file.seek(0, os.SEEK_END)
            if lock_file.tell() == 0:
                lock_file.write(b"\0")
                lock_file.flush()
            lock_file.seek(0)
            if os.name == "nt":
                msvcrt.locking(lock_file.fileno(), msvcrt.LK_LOCK, 1)
            else:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                lock_file.seek(0)
                if os.name == "nt":
                    msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


class PersistentKeyStore:
    """File-backed persistent store separating public registry metadata and private keys."""

    def __init__(self, state_dir: str | Path | None = None) -> None:
        self._base_dir = resolve_state_dir(state_dir) / "keyservice"
        self._registry_path = self._base_dir / "registry.json"
        self._private_dir = self._base_dir / "private"
        self._backups_dir = self._base_dir / "backups"
        self._lock_path = self._base_dir / ".keyservice.lock"

    @property
    def base_dir(self) -> Path:
        """Return the resolved keyservice state directory path."""
        return self._base_dir

    @property
    def registry_path(self) -> Path:
        """Return the path to the persistent public key registry."""
        return self._registry_path

    @property
    def private_dir(self) -> Path:
        """Return the path to the private key storage directory."""
        return self._private_dir

    @property
    def backups_dir(self) -> Path:
        """Return the path to the persistent backup directory."""
        return self._backups_dir

    def cleanup_stale_temp_files(self) -> None:
        """Remove orphaned temporary files left behind by interrupted writes."""
        for folder in (self._base_dir, self._private_dir, self._backups_dir):
            if not folder.exists():
                continue
            for entry in folder.iterdir():
                if entry.is_file() and entry.name.startswith(".") and entry.name.endswith(".tmp"):
                    try:
                        entry.unlink(missing_ok=True)
                    except OSError:
                        pass

    @contextmanager
    def locked(self) -> Iterator[None]:
        """Acquire both thread-level and OS-level cross-process exclusive locks."""
        with file_lock(self._lock_path):
            yield

    def load_state(
        self,
    ) -> tuple[dict[str, KeyRecord], int, list[RevocationRecord]]:
        """Load and integrity-verify records, revocation sequence, and revocation log."""
        self.cleanup_stale_temp_files()
        if not self._registry_path.exists():
            return {}, 0, []

        try:
            raw_text = self._registry_path.read_text(encoding="utf-8")
            payload = json.loads(raw_text)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise StorageIntegrityError("Failed to read or parse persistent key registry.") from exc

        if not isinstance(payload, dict):
            raise StorageIntegrityError("Persistent key registry must be a JSON object.")

        if payload.get("schema_version") != SCHEMA_VERSION:
            raise StorageIntegrityError(
                f"Unsupported key registry schema_version: {payload.get('schema_version')!r}"
            )

        raw_keys = payload.get("keys")
        if not isinstance(raw_keys, dict):
            raise StorageIntegrityError("Persistent key registry 'keys' field must be an object.")

        records: dict[str, KeyRecord] = {}
        for key_id, entry in raw_keys.items():
            record = KeyRecord.from_storage_dict(entry)
            if record.key_id != key_id:
                raise StorageIntegrityError(
                    f"Registry key mismatch: index {key_id!r} != record {record.key_id!r}"
                )
            records[key_id] = record

        last_revocation_seq = payload.get("last_revocation_seq", 0)
        if (
            not isinstance(last_revocation_seq, int)
            or isinstance(last_revocation_seq, bool)
            or last_revocation_seq < 0
        ):
            raise StorageIntegrityError("Persistent key registry has invalid last_revocation_seq.")

        raw_revocations = payload.get("revocations", [])
        if not isinstance(raw_revocations, list):
            raise StorageIntegrityError("Persistent key registry 'revocations' must be a list.")

        revocations: list[RevocationRecord] = []
        seen_event_ids: set[str] = set()
        max_seen_seq = 0
        for item in raw_revocations:
            rev = RevocationRecord.from_storage_dict(item)
            if rev.event_id in seen_event_ids:
                raise StorageIntegrityError("Duplicate revocation event_id in persistent registry.")
            seen_event_ids.add(rev.event_id)
            if rev.sequence_number > max_seen_seq:
                max_seen_seq = rev.sequence_number
            revocations.append(rev)

        if max_seen_seq > last_revocation_seq:
            raise StorageIntegrityError(
                "Persistent key registry revocation sequence counter is behind revocation log."
            )

        return records, last_revocation_seq, revocations

    def load_registry(self) -> dict[str, KeyRecord]:
        """Load and integrity-verify all KeyRecords from disk."""
        records, _, _ = self.load_state()
        return records

    def save_registry(
        self,
        records: dict[str, KeyRecord],
        *,
        last_revocation_seq: int | None = None,
        revocations: list[RevocationRecord] | None = None,
    ) -> None:
        """Atomically persist the complete public key registry and revocation metadata."""
        if last_revocation_seq is None or revocations is None:
            if self._registry_path.exists():
                _, existing_seq, existing_revs = self.load_state()
            else:
                existing_seq, existing_revs = 0, []
            if last_revocation_seq is None:
                last_revocation_seq = existing_seq
            if revocations is None:
                revocations = existing_revs

        payload = {
            "schema_version": SCHEMA_VERSION,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "last_revocation_seq": last_revocation_seq,
            "revocations": [
                rev.with_digest().to_storage_dict(include_digest=True)
                for rev in revocations
            ],
            "keys": {
                key_id: record.with_digest().to_storage_dict(include_digest=True)
                for key_id, record in records.items()
            },
        }
        encoded = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
        atomic_write_bytes(self._registry_path, encoded, file_mode=0o600, dir_mode=0o700)

    def save_private_key(self, key_id: str, secret_key: bytes) -> Path:
        """Atomically persist private key material in a restricted directory."""
        validate_key_id_filename(key_id)
        if not isinstance(secret_key, (bytes, bytearray)) or not secret_key:
            raise ValidationError("secret_key must be non-empty bytes.")

        secret_bytes = bytes(secret_key)
        payload = {
            "schema_version": SCHEMA_VERSION,
            "key_id": key_id,
            "algorithm": ALGORITHM,
            "secret_key_b64": base64.b64encode(secret_bytes).decode("ascii"),
            "secret_key_sha256": hashlib.sha256(secret_bytes).hexdigest(),
        }
        return self.save_private_key_payload(key_id, payload)

    def save_private_key_payload(self, key_id: str, payload: dict[str, object]) -> Path:
        """Validate and atomically persist a private key payload dictionary."""
        validate_key_id_filename(key_id)
        self.validate_private_key_payload(key_id, payload)
        encoded = json.dumps(payload, sort_keys=True).encode("utf-8")
        target = self._private_dir / f"{key_id}.key"
        atomic_write_bytes(target, encoded, file_mode=0o600, dir_mode=0o700)
        return target

    @staticmethod
    def validate_private_key_payload(key_id: str, payload: object) -> bytes:
        """Validate a private key payload and return the decoded secret key bytes."""
        validate_key_id_filename(key_id)
        if not isinstance(payload, dict):
            raise StorageIntegrityError("Private key payload must be a JSON object.")
        if payload.get("schema_version") != SCHEMA_VERSION:
            raise StorageIntegrityError("Private key payload has unsupported schema_version.")
        if payload.get("key_id") != key_id or payload.get("algorithm") != ALGORITHM:
            raise StorageIntegrityError("Private key payload metadata mismatch.")

        secret_b64 = payload.get("secret_key_b64")
        secret_sha = payload.get("secret_key_sha256")
        if not isinstance(secret_b64, str) or not isinstance(secret_sha, str):
            raise StorageIntegrityError("Private key payload is missing key material fields.")

        try:
            secret_bytes = base64.b64decode(secret_b64, validate=True)
        except Exception as exc:
            raise StorageIntegrityError("Private key payload base64 is malformed.") from exc

        if len(secret_bytes) != ML_KEM_SECRET_KEY_SIZE:
            raise StorageIntegrityError("Private key payload length does not match ML-KEM-768.")
        if hashlib.sha256(secret_bytes).hexdigest() != secret_sha:
            raise StorageIntegrityError("Private key payload SHA-256 integrity check failed.")
        return secret_bytes

    def load_private_key_payload(self, key_id: str) -> dict[str, object]:
        """Load and integrity-verify a private key payload for internal backup use."""
        validate_key_id_filename(key_id)
        target = self._private_dir / f"{key_id}.key"
        try:
            payload = json.loads(target.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise StorageIntegrityError(
                f"Failed to read private key record for {key_id!r}."
            ) from exc
        self.validate_private_key_payload(key_id, payload)
        return payload

    def delete_private_key_if_exists(self, key_id: str) -> None:
        """Remove a private key file during rollback if registry persistence fails."""
        validate_key_id_filename(key_id)
        target = self._private_dir / f"{key_id}.key"
        try:
            target.unlink(missing_ok=True)
        except OSError:
            pass
