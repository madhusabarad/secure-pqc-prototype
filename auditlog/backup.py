"""Post-quantum signed backups with rollback protection and revocation preservation.

Security guarantees:
1. Manifest {backup_id, key_version, sha256 of content, created_time} signed with ML-DSA-65.
2. Verify signature and sha256 digest FIRST before touching any state.
3. Reject restores where backup key_version < current state key_version (rollback protection).
4. Never let restore un-revoke an actor: merged revoked = current.revoked UNION backup.revoked.
5. All failures reported generically without printing or leaking sensitive contents.
"""

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
from typing import Any, Dict, Optional, Tuple

from pqcrypto.sign import ml_dsa_65

from auditlog import audit
from auditlog.audit import canonical_json, get_or_create_signing_key
from auditlog.store import file_lock, fsync_dir_if_supported, load_state, save_state


class BackupError(Exception):
    """Generic backup error to prevent leaking secrets."""
    pass


def create_backup(dest_path: Path) -> Dict[str, Any]:
    """Create a signed backup of current state."""
    with file_lock():
        state = load_state()
        if state is None:
            raise BackupError("Cannot backup uninitialized state.")

        backup_id = f"bak_{secrets.token_hex(12)}"
        key_version = state.get("key_version", 1)
        created_time = datetime.now(timezone.utc).isoformat()

        content_data = {
            "backup_id": backup_id,
            "key_version": key_version,
            "state": state,
        }
        content_bytes = canonical_json(content_data).encode("utf-8")
        content_sha256 = hashlib.sha256(content_bytes).hexdigest()

        manifest = {
            "backup_id": backup_id,
            "created_time": created_time,
            "key_version": key_version,
            "sha256": content_sha256,
        }
        manifest_bytes = canonical_json(manifest).encode("utf-8")

        pk, sk = get_or_create_signing_key()
        sig = ml_dsa_65.sign(sk, manifest_bytes)

        backup_bundle = {
            "manifest": manifest,
            "signature": sig.hex(),
            "public_key": pk.hex(),
            "content": content_data,
        }

        dest = Path(dest_path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp_dest = dest.with_name(f"{dest.name}.tmp.{secrets.token_hex(8)}")
        with open(tmp_dest, "w", encoding="utf-8") as f:
            f.write(canonical_json(backup_bundle))
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_dest, dest)
        fsync_dir_if_supported(dest.parent)

        # Audit backup creation
        audit.append_event(
            actor="system",
            action="backup_create",
            outcome="success",
            correlation_id=backup_id,
        )
        return manifest


def restore_backup(src_path: Path) -> Dict[str, Any]:
    """Restore state from a signed backup file."""
    src = Path(src_path)
    if not src.exists():
        raise BackupError("Backup file does not exist.")

    try:
        with open(src, "r", encoding="utf-8") as f:
            bundle = json.load(f)
    except Exception:
        raise BackupError("Malformed backup container.")

    if not isinstance(bundle, dict):
        raise BackupError("Invalid backup structure.")

    manifest = bundle.get("manifest")
    sig_hex = bundle.get("signature")
    pk_hex = bundle.get("public_key")
    content_data = bundle.get("content")

    if not manifest or not sig_hex or not pk_hex or not content_data:
        raise BackupError("Incomplete backup bundle.")

    # 1. Verify ML-DSA-65 signature on manifest
    try:
        pk = bytes.fromhex(pk_hex)
        sig = bytes.fromhex(sig_hex)
        manifest_bytes = canonical_json(manifest).encode("utf-8")
        if not ml_dsa_65.verify(pk, manifest_bytes, sig):
            raise BackupError("Backup signature verification failed.")
    except Exception:
        raise BackupError("Backup signature verification failed.")

    # 2. Verify sha256 digest of content
    content_bytes = canonical_json(content_data).encode("utf-8")
    expected_sha256 = manifest.get("sha256")
    actual_sha256 = hashlib.sha256(content_bytes).hexdigest()
    if expected_sha256 != actual_sha256:
        raise BackupError("Backup content hash mismatch.")

    # 3. Check rollback protection & state update with lock
    with file_lock():
        current_state = load_state()
        if current_state is not None:
            current_kv = current_state.get("key_version", 1)
            backup_kv = manifest.get("key_version", 0)
            if backup_kv < current_kv:
                raise BackupError(f"Refusing restore: backup key_version ({backup_kv}) older than current ({current_kv}).")

            # Revocation preservation: UNION of current revoked and backup revoked
            current_revoked = set(current_state.get("revoked", []))
            backup_revoked = set(content_data.get("state", {}).get("revoked", []))
            merged_revoked = sorted(list(current_revoked.union(backup_revoked)))
        else:
            merged_revoked = content_data.get("state", {}).get("revoked", [])

        restored_state = dict(content_data.get("state", {}))
        restored_state["revoked"] = merged_revoked

        # Save restored state atomically
        save_state(restored_state)

        # Audit restoration
        audit.append_event(
            actor="system",
            action="backup_restore",
            outcome="success",
            correlation_id=manifest.get("backup_id", ""),
        )

        return {
            "restored": True,
            "backup_id": manifest.get("backup_id"),
            "key_version": restored_state.get("key_version"),
        }
