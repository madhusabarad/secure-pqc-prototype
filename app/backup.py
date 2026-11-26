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

from app import audit
from app.audit import canonical_json, get_or_create_signing_key
from app.store import file_lock, fsync_dir_if_supported, load_state, save_state


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
        raise BackupError("Invalid backup container format.")

    manifest = bundle.get("manifest")
    sig_hex = bundle.get("signature")
    pk_hex = bundle.get("public_key")
    content = bundle.get("content")

    if not all([manifest, sig_hex, pk_hex, content]):
        raise BackupError("Incomplete backup bundle.")

    # 1. Verify ML-DSA-65 signature on manifest FIRST
    try:
        pk = bytes.fromhex(pk_hex)
        sig = bytes.fromhex(sig_hex)
        manifest_bytes = canonical_json(manifest).encode("utf-8")

        sig_ok = False
        try:
            sig_ok = ml_dsa_65.verify(pk, manifest_bytes, sig)
        except Exception:
            sig_ok = False

        if not sig_ok:
            raise BackupError("Backup signature verification failed.")
    except Exception as e:
        if isinstance(e, BackupError):
            raise
        raise BackupError("Invalid cryptographic data in backup.")

    # 2. Verify sha256 digest of content
    content_bytes = canonical_json(content).encode("utf-8")
    computed_sha256 = hashlib.sha256(content_bytes).hexdigest()
    if computed_sha256 != manifest.get("sha256"):
        raise BackupError("Backup content hash verification failed.")

    # 3. Apply state under lock with rollback and revocation protection
    with file_lock():
        current_state = load_state()
        if current_state is not None:
            # Check key version monotonicity
            current_version = current_state.get("key_version", 1)
            backup_version = manifest.get("key_version", 1)
            if backup_version < current_version:
                raise BackupError(f"Rejected: backup key_version ({backup_version}) is older than current ({current_version}).")

            current_revoked = set(current_state.get("revoked", []))
        else:
            current_revoked = set()

        backup_state = content.get("state", {})
        backup_revoked = set(backup_state.get("revoked", []))

        # Invariant: Never allow restore to un-revoke an actor (union rule)
        merged_revoked = sorted(list(current_revoked | backup_revoked))

        new_state = dict(backup_state)
        new_state["revoked"] = merged_revoked

        save_state(new_state)

        # Audit restoration
        audit.append_event(
            actor="system",
            action="backup_restore",
            outcome="success",
            correlation_id=manifest.get("backup_id", ""),
        )

    return {
        "status": "success",
        "backup_id": manifest.get("backup_id"),
        "key_version": new_state.get("key_version"),
    }
