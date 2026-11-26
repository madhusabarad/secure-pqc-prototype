"""Backup creation, SHA-256 integrity verification, and safe lifecycle restoration."""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pqcrypto.kem import ml_kem_768

from .exceptions import BackupIntegrityError, StorageIntegrityError, ValidationError
from .models import (
    SCHEMA_VERSION,
    STATUS_REVOKED,
    KeyRecord,
    RevocationRecord,
    parse_utc_timestamp,
)
from .storage import PersistentKeyStore, atomic_write_bytes

logger = logging.getLogger("keyservice.backup")
logger.addHandler(logging.NullHandler())


def _compute_backup_digest(body: dict[str, Any]) -> str:
    encoded = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _validate_backup_path(backup_path: str | Path) -> Path:
    if not isinstance(backup_path, (str, Path)):
        raise ValidationError("backup_path must be a string or Path.")
    raw = str(backup_path).strip()
    if not raw:
        raise ValidationError("backup_path must not be empty.")
    return Path(raw).expanduser().resolve()


def _parse_and_validate_backup(
    backup_path: str | Path,
) -> tuple[
    dict[str, Any],
    dict[str, KeyRecord],
    int,
    list[RevocationRecord],
    dict[str, dict[str, object]],
]:
    path = _validate_backup_path(backup_path)
    if not path.exists() or not path.is_file():
        raise BackupIntegrityError(f"Backup file does not exist: {path}")

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BackupIntegrityError("Failed to read or parse backup file.") from exc

    if not isinstance(payload, dict):
        raise BackupIntegrityError("Backup payload must be a JSON object.")

    required_top = {
        "schema_version",
        "backup_id",
        "created_at",
        "last_revocation_seq",
        "revocations",
        "keys",
        "private_keys",
        "integrity_sha256",
    }
    if not required_top.issubset(payload.keys()):
        raise BackupIntegrityError("Backup file is missing required fields.")

    if payload.get("schema_version") != SCHEMA_VERSION:
        raise BackupIntegrityError(
            f"Unsupported backup schema_version: {payload.get('schema_version')!r}"
        )

    backup_id = payload.get("backup_id")
    if not isinstance(backup_id, str) or not backup_id.strip():
        raise BackupIntegrityError("Backup 'backup_id' must be a non-empty string.")

    parse_utc_timestamp(payload["created_at"], "backup.created_at")

    provided_digest = payload.get("integrity_sha256")
    if not isinstance(provided_digest, str) or not provided_digest:
        raise BackupIntegrityError("Backup is missing integrity_sha256.")

    body = {k: v for k, v in payload.items() if k != "integrity_sha256"}
    expected_digest = _compute_backup_digest(body)
    if provided_digest != expected_digest:
        raise BackupIntegrityError("Backup integrity_sha256 verification failed.")

    last_seq = payload["last_revocation_seq"]
    if not isinstance(last_seq, int) or isinstance(last_seq, bool) or last_seq < 0:
        raise BackupIntegrityError("Backup 'last_revocation_seq' is invalid.")

    raw_keys = payload["keys"]
    if not isinstance(raw_keys, dict):
        raise BackupIntegrityError("Backup 'keys' must be a JSON object.")

    records: dict[str, KeyRecord] = {}
    for key_id, raw_rec in raw_keys.items():
        try:
            record = KeyRecord.from_storage_dict(raw_rec)
        except StorageIntegrityError as exc:
            raise BackupIntegrityError(f"Backup key record invalid: {exc}") from exc
        if record.key_id != key_id:
            raise BackupIntegrityError(
                f"Backup key index mismatch: {key_id!r} != {record.key_id!r}"
            )
        if record.status == STATUS_REVOKED and record.revoked_at is None:
            raise BackupIntegrityError(
                f"Backup revoked key {key_id!r} is missing revoked_at timestamp."
            )
        if record.revoked_at is not None and record.status != STATUS_REVOKED:
            raise BackupIntegrityError(
                f"Backup key {key_id!r} has revoked_at set while status is {record.status!r}."
            )
        records[key_id] = record

    raw_revs = payload["revocations"]
    if not isinstance(raw_revs, list):
        raise BackupIntegrityError("Backup 'revocations' must be a list.")

    revocations: list[RevocationRecord] = []
    seen_event_ids: set[str] = set()
    for raw_rev in raw_revs:
        try:
            rev = RevocationRecord.from_storage_dict(raw_rev)
        except StorageIntegrityError as exc:
            raise BackupIntegrityError(f"Backup revocation record invalid: {exc}") from exc
        if rev.event_id in seen_event_ids:
            raise BackupIntegrityError("Backup contains duplicate revocation event_id.")
        seen_event_ids.add(rev.event_id)
        if rev.sequence_number > last_seq:
            raise BackupIntegrityError("Backup revocation sequence exceeds last_revocation_seq.")
        rec = records.get(rev.key_id)
        if rec is not None and rec.status != STATUS_REVOKED:
            raise BackupIntegrityError(
                f"Backup revocation history conflicts with non-revoked key {rev.key_id!r}."
            )
        revocations.append(rev)

    raw_private = payload["private_keys"]
    if not isinstance(raw_private, dict):
        raise BackupIntegrityError("Backup 'private_keys' must be a JSON object.")

    private_keys: dict[str, dict[str, object]] = {}
    for key_id, priv_payload in raw_private.items():
        if key_id not in records:
            raise BackupIntegrityError(
                f"Backup contains private key for unknown key_id {key_id!r}."
            )
        try:
            sk_bytes = PersistentKeyStore.validate_private_key_payload(key_id, priv_payload)
        except (StorageIntegrityError, ValidationError) as exc:
            raise BackupIntegrityError(f"Backup private key invalid for {key_id!r}: {exc}") from exc

        pk_bytes = base64.b64decode(records[key_id].public_key_b64)
        ct, shared_enc = ml_kem_768.encrypt(pk_bytes)
        shared_dec = ml_kem_768.decrypt(sk_bytes, ct)
        if shared_enc != shared_dec:
            raise BackupIntegrityError(
                f"Backup ML-KEM-768 keypair consistency check failed for {key_id!r}."
            )
        private_keys[key_id] = priv_payload

    for key_id, rec in records.items():
        if rec.status != STATUS_REVOKED and key_id not in private_keys:
            raise BackupIntegrityError(
                f"Backup is missing private key material for non-revoked key {key_id!r}."
            )

    return payload, records, last_seq, revocations, private_keys


def create_backup(
    store: PersistentKeyStore,
    backup_path: str | Path | None = None,
) -> dict[str, Any]:
    """Create an integrity-verified atomic backup of key records, revocations, and keys."""
    with store.locked():
        records, last_seq, revocations = store.load_state()
        private_keys: dict[str, dict[str, object]] = {}
        for key_id, record in records.items():
            if record.status != STATUS_REVOKED:
                private_keys[key_id] = store.load_private_key_payload(key_id)

        backup_id = f"bkp-{uuid.uuid4().hex}"
        created_at = datetime.now(timezone.utc).isoformat()
        body: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "backup_id": backup_id,
            "created_at": created_at,
            "last_revocation_seq": last_seq,
            "revocations": [
                rev.with_digest().to_storage_dict(include_digest=True)
                for rev in revocations
            ],
            "keys": {
                key_id: record.with_digest().to_storage_dict(include_digest=True)
                for key_id, record in records.items()
            },
            "private_keys": private_keys,
        }
        integrity_sha256 = _compute_backup_digest(body)
        envelope = {"integrity_sha256": integrity_sha256, **body}

        target = (
            _validate_backup_path(backup_path)
            if backup_path is not None
            else (store.backups_dir / f"{backup_id}.json")
        )
        encoded = json.dumps(envelope, indent=2, sort_keys=True).encode("utf-8")
        atomic_write_bytes(target, encoded, file_mode=0o600, dir_mode=0o700)

    logger.info(
        "Created key backup backup_id=%s keys=%d revocations=%d integrity=%s",
        backup_id,
        len(records),
        len(revocations),
        integrity_sha256,
    )
    return {
        "backup_id": backup_id,
        "backup_path": str(target),
        "created_at": created_at,
        "key_count": len(records),
        "revocation_count": len(revocations),
        "last_revocation_seq": last_seq,
        "integrity_sha256": integrity_sha256,
    }


def verify_backup(backup_path: str | Path) -> dict[str, Any]:
    """Validate backup integrity, key records, revocations, and ML-KEM-768 keypairs."""
    payload, records, last_seq, revocations, _ = _parse_and_validate_backup(backup_path)
    return {
        "valid": True,
        "backup_id": payload["backup_id"],
        "created_at": payload["created_at"],
        "key_count": len(records),
        "revocation_count": len(revocations),
        "last_revocation_seq": last_seq,
        "integrity_sha256": payload["integrity_sha256"],
    }


def restore_backup(
    store: PersistentKeyStore,
    backup_path: str | Path,
) -> dict[str, Any]:
    """Restore validated backup state atomically without reactivating revoked keys."""
    with store.locked():
        payload, backup_records, backup_seq, backup_revs, private_keys = (
            _parse_and_validate_backup(backup_path)
        )

        live_records: dict[str, KeyRecord] = {}
        live_seq = 0
        live_revs: list[RevocationRecord] = []
        try:
            live_records, live_seq, live_revs = store.load_state()
        except StorageIntegrityError:
            pass

        merged_revs_by_id: dict[str, RevocationRecord] = {
            rev.event_id: rev for rev in backup_revs
        }
        for rev in live_revs:
            merged_revs_by_id.setdefault(rev.event_id, rev)
        merged_revs = sorted(
            merged_revs_by_id.values(),
            key=lambda item: (item.sequence_number, item.event_id),
        )
        revoked_by_key_id: dict[str, RevocationRecord] = {
            rev.key_id: rev for rev in merged_revs
        }

        restored_records: dict[str, KeyRecord] = {}
        for key_id, bkp_rec in backup_records.items():
            live_rec = live_records.get(key_id)
            rev_rec = revoked_by_key_id.get(key_id)
            if live_rec is not None and live_rec.status == STATUS_REVOKED:
                restored_records[key_id] = live_rec.with_digest()
            elif rev_rec is not None and bkp_rec.status != STATUS_REVOKED:
                restored_records[key_id] = KeyRecord(
                    key_id=bkp_rec.key_id,
                    user=bkp_rec.user,
                    device=bkp_rec.device,
                    algorithm=bkp_rec.algorithm,
                    version=bkp_rec.version,
                    status=STATUS_REVOKED,
                    public_key_b64=bkp_rec.public_key_b64,
                    public_key_sha256=bkp_rec.public_key_sha256,
                    created_at=bkp_rec.created_at,
                    updated_at=rev_rec.revoked_at,
                    revoked_at=rev_rec.revoked_at,
                    retired_at=bkp_rec.retired_at,
                    grace_until=bkp_rec.grace_until,
                    grace_period_seconds=bkp_rec.grace_period_seconds,
                    previous_key_id=bkp_rec.previous_key_id,
                    revocation_event_id=rev_rec.event_id,
                    revocation_seq=rev_rec.sequence_number,
                ).with_digest()
            else:
                restored_records[key_id] = bkp_rec.with_digest()

        for key_id, live_rec in live_records.items():
            if key_id not in restored_records and live_rec.status == STATUS_REVOKED:
                restored_records[key_id] = live_rec.with_digest()

        restored_seq = max(
            backup_seq,
            live_seq,
            max((rev.sequence_number for rev in merged_revs), default=0),
        )

        newly_written_keys: list[str] = []
        try:
            for key_id, rec in restored_records.items():
                if rec.status != STATUS_REVOKED and key_id in private_keys:
                    target = store.private_dir / f"{key_id}.key"
                    if not target.exists():
                        newly_written_keys.append(key_id)
                    store.save_private_key_payload(key_id, private_keys[key_id])

            store.save_registry(
                restored_records,
                last_revocation_seq=restored_seq,
                revocations=merged_revs,
            )
        except Exception:
            for key_id in newly_written_keys:
                store.delete_private_key_if_exists(key_id)
            raise

    revoked_count = sum(1 for r in restored_records.values() if r.status == STATUS_REVOKED)
    logger.info(
        "Restored key backup backup_id=%s keys=%d revoked=%d seq=%d",
        payload["backup_id"],
        len(restored_records),
        revoked_count,
        restored_seq,
    )
    return {
        "restored": True,
        "backup_id": payload["backup_id"],
        "restored_key_count": len(restored_records),
        "revoked_key_count": revoked_count,
        "last_revocation_seq": restored_seq,
        "integrity_sha256": payload["integrity_sha256"],
    }
