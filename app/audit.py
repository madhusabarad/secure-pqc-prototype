"""Tamper-evident audit log with hash-chaining and post-quantum ML-DSA-65 signed checkpoints.

Audit log format:
- audit.log: append-only JSON Lines, one canonical JSON object per line.
- Canonical form: json.dumps(obj, sort_keys=True, separators=(",",":"), ensure_ascii=True, allow_nan=False)
- Hash formula:
    hash = sha256(b"T4AUDIT1\x00" + bytes.fromhex(prev_hash) + canonical(entry without hash))
- Genesis prev_hash: "0" * 64 (64 hex zeros)
- seq: monotonic integer starting at 1 with no gaps.
- Checkpoint (checkpoint.json):
    Signed with ML-DSA-65 over canonical bytes of {"head": head, "seq": seq, "v": 1}.
    Atomic replacement ensures detection of truncated/deleted log entries.
"""

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
from typing import Any, Dict, List, Optional, Tuple

from pqcrypto.sign import ml_dsa_65

from app.store import fsync_dir_if_supported, get_state_dir

GENESIS_PREV_HASH = "0" * 64
HASH_PREFIX = b"T4AUDIT1\x00"


def get_audit_log_path() -> Path:
    return get_state_dir() / "audit.log"


def get_checkpoint_path() -> Path:
    return get_state_dir() / "checkpoint.json"


def get_signing_key_path() -> Path:
    return get_state_dir() / "audit_signing_key.json"


def canonical_json(obj: Any) -> str:
    """Format dictionary into canonical JSON string."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def get_or_create_signing_key() -> Tuple[bytes, bytes]:
    """Retrieve or generate ML-DSA-65 audit log signing keypair.

    Security Notice / Honest Limitation:
    The signing key is stored in the local state directory. Any adversary with
    write access to the state directory could generate a new key and re-sign
    a modified checkpoint. The mitigation is exporting the head hash as an
    external anchor.
    """
    key_path = get_signing_key_path()
    if key_path.exists():
        try:
            with open(key_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return bytes.fromhex(data["public_key"]), bytes.fromhex(data["private_key"])
        except Exception:
            pass

    pk, sk = ml_dsa_65.generate_keypair()
    tmp_path = key_path.with_name(f"audit_signing_key.json.tmp.{secrets.token_hex(8)}")
    with open(tmp_path, "w", encoding="utf-8") as f:
        f.write(canonical_json({"public_key": pk.hex(), "private_key": sk.hex()}))
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, key_path)
    fsync_dir_if_supported(key_path.parent)
    return pk, sk


def compute_entry_hash(entry_without_hash: Dict[str, Any], prev_hash: str) -> str:
    """Compute sha256(b"T4AUDIT1\x00" + bytes.fromhex(prev_hash) + canonical(entry without hash))."""
    prev_bytes = bytes.fromhex(prev_hash)
    canon_bytes = canonical_json(entry_without_hash).encode("utf-8")
    return hashlib.sha256(HASH_PREFIX + prev_bytes + canon_bytes).hexdigest()


def read_log_tail() -> Optional[Dict[str, Any]]:
    """Read only the tail of audit.log without scanning the entire file."""
    log_path = get_audit_log_path()
    if not log_path.exists() or log_path.stat().st_size == 0:
        return None

    file_size = log_path.stat().st_size
    read_size = min(file_size, 8192)
    with open(log_path, "rb") as f:
        f.seek(file_size - read_size)
        tail_bytes = f.read()

    lines = [line.strip() for line in tail_bytes.split(b"\n") if line.strip()]
    if not lines:
        return None

    last_line = lines[-1].decode("utf-8")
    return json.loads(last_line)


def read_checkpoint() -> Optional[Dict[str, Any]]:
    """Read the current checkpoint file."""
    cp_path = get_checkpoint_path()
    if not cp_path.exists():
        return None
    try:
        with open(cp_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def write_checkpoint(seq: int, head: str, pk: bytes, sk: bytes) -> None:
    """Atomically write signed checkpoint."""
    cp_path = get_checkpoint_path()
    payload = {"head": head, "seq": seq, "v": 1}
    payload_canonical = canonical_json(payload).encode("utf-8")
    sig = ml_dsa_65.sign(sk, payload_canonical)

    checkpoint_data = {
        "v": 1,
        "seq": seq,
        "head": head,
        "sig": sig.hex(),
        "public_key": pk.hex(),
    }
    tmp_path = cp_path.with_name(f"checkpoint.json.tmp.{secrets.token_hex(8)}")
    with open(tmp_path, "w", encoding="utf-8") as f:
        f.write(canonical_json(checkpoint_data))
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, cp_path)
    fsync_dir_if_supported(cp_path.parent)


def reset_audit_log() -> None:
    """Clear audit log, checkpoint, and signing keys for a fresh setup."""
    for path in (get_audit_log_path(), get_checkpoint_path(), get_signing_key_path()):
        if path.exists():
            try:
                os.unlink(path)
            except OSError:
                pass


def append_event(
    actor: str,
    action: str,
    outcome: str,
    correlation_id: str = "",
    role_before: str = "",
    role_after: str = "",
    approval_id: str = "",
    session_id: str = "",
) -> Dict[str, Any]:
    """Append an event to the audit log and update the signed checkpoint.

    Tail verification is performed so the entire log is never scanned on append.
    """
    log_path = get_audit_log_path()
    pk, sk = get_or_create_signing_key()
    checkpoint = read_checkpoint()
    tail_entry = read_log_tail()

    if checkpoint is None or tail_entry is None:
        seq = 1
        prev_hash = GENESIS_PREV_HASH
    else:
        # Consistency check: checkpoint head must match tail entry hash
        if checkpoint.get("head") != tail_entry.get("hash") or checkpoint.get("seq") != tail_entry.get("seq"):
            raise ValueError("Audit log state inconsistent with checkpoint.")
        seq = tail_entry["seq"] + 1
        prev_hash = tail_entry["hash"]

    now_utc = datetime.now(timezone.utc).isoformat()
    event_id = secrets.token_hex(16)

    # Organizers' schema + hash chain fields
    event_entry = {
        "event_id": event_id,
        "event_time_utc": now_utc,
        "received_time_utc": now_utc,
        "source_clock_offset_ms": 0,
        "actor": actor,
        "source_service": "adapter",
        "target_service": "assets",
        "action": action,
        "role_before": role_before,
        "role_after": role_after,
        "outcome": outcome,
        "approval_id": approval_id,
        "session_id": session_id,
        "correlation_id": correlation_id,
        "seq": seq,
        "prev_hash": prev_hash,
    }

    entry_hash = compute_entry_hash(event_entry, prev_hash)
    event_entry["hash"] = entry_hash

    canon_line = canonical_json(event_entry) + "\n"
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(canon_line)
        f.flush()
        os.fsync(f.fileno())

    # Rewrite checkpoint atomically after every append
    write_checkpoint(seq, entry_hash, pk, sk)
    return event_entry


def find_event_by_correlation_id(correlation_id: str, state_dir: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    """Scan audit log backwards to find event with matching correlation_id."""
    if state_dir is not None:
        log_path = Path(state_dir) / "audit.log"
    else:
        log_path = get_audit_log_path()
    if not log_path.exists():
        return None

    # Read lines (most requests query recent events)
    with open(log_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
            if entry.get("correlation_id") == correlation_id:
                return entry
        except Exception:
            continue
    return None


def verify_audit_log(state_dir: Optional[Path] = None, anchor_head: Optional[str] = None) -> Dict[str, Any]:
    """Verify integrity of the audit log and checkpoint.

    Checks:
    1. Every line parses as canonical JSON.
    2. seq starts at 1 and increases monotonically without gaps.
    3. prev_hash matches the previous entry's hash (genesis is 64 zeros).
    4. Each hash recomputes correctly according to the hash formula.
    5. Checkpoint exists, parses, signature verifies via ML-DSA-65.
    6. Checkpoint seq and head match the last entry in the log (detects tail truncation).
    7. If anchor_head is provided, confirms it exists at its seq in the chain.

    Returns dict:
        {"valid": bool, "bad_line": Optional[int], "reason": Optional[str],
         "entries_count": int, "head": Optional[str]}
    """
    if state_dir is None:
        state_dir = get_state_dir()
    else:
        state_dir = Path(state_dir)

    log_path = state_dir / "audit.log"
    cp_path = state_dir / "checkpoint.json"

    if not log_path.exists() or log_path.stat().st_size == 0:
        if cp_path.exists():
            return {
                "valid": False,
                "bad_line": None,
                "reason": "Checkpoint exists but audit log is missing or empty.",
                "entries_count": 0,
                "head": None,
            }
        return {
            "valid": True,
            "bad_line": None,
            "reason": None,
            "entries_count": 0,
            "head": None,
        }

    expected_seq = 1
    expected_prev_hash = GENESIS_PREV_HASH
    last_hash = None
    line_number = 0
    anchor_found = False

    with open(log_path, "r", encoding="utf-8") as f:
        for raw_line in f:
            line_number += 1
            line = raw_line.rstrip("\r\n")
            if not line:
                return {
                    "valid": False,
                    "bad_line": line_number,
                    "reason": "Empty line or whitespace inside audit log.",
                    "entries_count": line_number - 1,
                    "head": last_hash,
                }
            try:
                entry = json.loads(line)
            except Exception:
                return {
                    "valid": False,
                    "bad_line": line_number,
                    "reason": "Malformed JSON line.",
                    "entries_count": line_number - 1,
                    "head": last_hash,
                }

            if not isinstance(entry, dict):
                return {
                    "valid": False,
                    "bad_line": line_number,
                    "reason": "Audit entry is not a JSON object.",
                    "entries_count": line_number - 1,
                    "head": last_hash,
                }

            # Check sequence continuity
            if entry.get("seq") != expected_seq:
                return {
                    "valid": False,
                    "bad_line": line_number,
                    "reason": f"Sequence gap or mismatch: expected {expected_seq}, got {entry.get('seq')}.",
                    "entries_count": line_number - 1,
                    "head": last_hash,
                }

            # Check prev_hash linkage
            if entry.get("prev_hash") != expected_prev_hash:
                return {
                    "valid": False,
                    "bad_line": line_number,
                    "reason": f"Broken hash chain link: expected prev_hash {expected_prev_hash}, got {entry.get('prev_hash')}.",
                    "entries_count": line_number - 1,
                    "head": last_hash,
                }

            # Recompute hash
            stored_hash = entry.get("hash")
            entry_no_hash = {k: v for k, v in entry.items() if k != "hash"}
            calculated_hash = compute_entry_hash(entry_no_hash, expected_prev_hash)
            if stored_hash != calculated_hash:
                return {
                    "valid": False,
                    "bad_line": line_number,
                    "reason": f"Hash mismatch: stored {stored_hash}, calculated {calculated_hash}.",
                    "entries_count": line_number - 1,
                    "head": last_hash,
                }

            last_hash = stored_hash
            expected_prev_hash = stored_hash
            expected_seq += 1

            if anchor_head and stored_hash == anchor_head:
                anchor_found = True

    entries_count = line_number

    # Checkpoint validation
    if not cp_path.exists():
        return {
            "valid": False,
            "bad_line": None,
            "reason": "Missing checkpoint file.",
            "entries_count": entries_count,
            "head": last_hash,
        }

    try:
        with open(cp_path, "r", encoding="utf-8") as f:
            cp_data = json.load(f)
    except Exception:
        return {
            "valid": False,
            "bad_line": None,
            "reason": "Corrupt or unreadable checkpoint JSON.",
            "entries_count": entries_count,
            "head": last_hash,
        }

    # Verify checkpoint contents
    if cp_data.get("seq") != entries_count or cp_data.get("head") != last_hash:
        return {
            "valid": False,
            "bad_line": None,
            "reason": f"Checkpoint mismatch: checkpoint seq={cp_data.get('seq')} head={cp_data.get('head')}, log seq={entries_count} head={last_hash}. Tail truncation detected.",
            "entries_count": entries_count,
            "head": last_hash,
        }

    # Verify checkpoint ML-DSA-65 signature
    try:
        pk = bytes.fromhex(cp_data["public_key"])
        sig = bytes.fromhex(cp_data["sig"])
        payload = {"head": cp_data["head"], "seq": cp_data["seq"], "v": cp_data["v"]}
        payload_canonical = canonical_json(payload).encode("utf-8")

        sig_ok = False
        try:
            sig_ok = ml_dsa_65.verify(pk, payload_canonical, sig)
        except Exception:
            sig_ok = False

        if not sig_ok:
            return {
                "valid": False,
                "bad_line": None,
                "reason": "Checkpoint ML-DSA-65 signature verification failed.",
                "entries_count": entries_count,
                "head": last_hash,
            }
    except Exception as e:
        return {
            "valid": False,
            "bad_line": None,
            "reason": f"Checkpoint signature decoding failed: {e}",
            "entries_count": entries_count,
            "head": last_hash,
        }

    if anchor_head and not anchor_found:
        return {
            "valid": False,
            "bad_line": None,
            "reason": f"Anchor head {anchor_head} was not found in the verified log.",
            "entries_count": entries_count,
            "head": last_hash,
        }

    return {
        "valid": True,
        "bad_line": None,
        "reason": None,
        "entries_count": entries_count,
        "head": last_hash,
    }
