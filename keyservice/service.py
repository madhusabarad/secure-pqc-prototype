"""Core key management service and agreed public interfaces."""

from __future__ import annotations

import base64
import logging
import math
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .backup import (
    create_backup as _create_backup,
    restore_backup as _restore_backup,
    verify_backup as _verify_backup,
)
from .crypto import generate_ml_kem_768_keypair, public_key_fingerprint
from .exceptions import (
    DuplicateDeviceError,
    KeyNotFoundError,
    NoActiveKeyError,
    ValidationError,
)
from .models import (
    ALGORITHM,
    DEFAULT_GRACE_PERIOD_SECONDS,
    STATUS_ACTIVE,
    STATUS_EXPIRED,
    STATUS_RETIRING,
    STATUS_REVOKED,
    KeyRecord,
    RevocationRecord,
    unknown_key_status_dict,
)
from .storage import PersistentKeyStore, resolve_state_dir, validate_key_id_filename

logger = logging.getLogger("keyservice")
logger.addHandler(logging.NullHandler())

_MAX_IDENTIFIER_LENGTH = 128
_GRACE_ENV_VARS = ("TRACK4_KEY_GRACE_PERIOD_SECONDS", "TRACK4_GRACE_PERIOD_SECONDS")


def _validate_identifier(value: object, field_name: str) -> str:
    """Validate user or device identifiers without altering or logging secrets."""
    if not isinstance(value, str):
        raise ValidationError(f"{field_name} must be a string.")
    if not value or not value.strip():
        raise ValidationError(f"{field_name} must be a non-empty string.")
    if value != value.strip():
        raise ValidationError(f"{field_name} must not have leading or trailing whitespace.")
    if len(value) > _MAX_IDENTIFIER_LENGTH:
        raise ValidationError(
            f"{field_name} must not exceed {_MAX_IDENTIFIER_LENGTH} characters."
        )
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise ValidationError(f"{field_name} must not contain control characters.")
    return value


def _validate_grace_period(value: object) -> float:
    """Validate a non-negative finite grace period in seconds."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValidationError("grace_period_seconds must be a non-negative number.")
    numeric = float(value)
    if not math.isfinite(numeric) or numeric < 0.0:
        raise ValidationError("grace_period_seconds must be a finite non-negative number.")
    return numeric


def resolve_grace_period_seconds(explicit: int | float | None = None) -> float:
    """Resolve the retiring-key grace period from argument, environment, or default."""
    if explicit is not None:
        return _validate_grace_period(explicit)

    for env_name in _GRACE_ENV_VARS:
        raw = os.environ.get(env_name)
        if raw is not None and raw.strip():
            try:
                parsed = float(raw.strip())
            except ValueError as exc:
                raise ValidationError(f"{env_name} must be a valid number.") from exc
            return _validate_grace_period(parsed)

    return DEFAULT_GRACE_PERIOD_SECONDS


def _normalize_now(now: datetime | None) -> datetime:
    """Return a timezone-aware UTC datetime."""
    if now is None:
        return datetime.now(timezone.utc)
    if not isinstance(now, datetime):
        raise ValidationError("now must be a datetime instance.")
    if now.tzinfo is None:
        return now.replace(tzinfo=timezone.utc)
    return now.astimezone(timezone.utc)


def _materialize_expired_records(records: dict[str, KeyRecord], now: datetime) -> None:
    """Persist expired status for any retiring key whose grace window has elapsed."""
    now_iso = now.isoformat()
    for key_id, record in list(records.items()):
        if record.status == STATUS_RETIRING and record.effective_status(now=now) == STATUS_EXPIRED:
            records[key_id] = KeyRecord(
                key_id=record.key_id,
                user=record.user,
                device=record.device,
                algorithm=record.algorithm,
                version=record.version,
                status=STATUS_EXPIRED,
                public_key_b64=record.public_key_b64,
                public_key_sha256=record.public_key_sha256,
                created_at=record.created_at,
                updated_at=now_iso,
                revoked_at=record.revoked_at,
                retired_at=record.retired_at,
                grace_until=record.grace_until,
                grace_period_seconds=record.grace_period_seconds,
                previous_key_id=record.previous_key_id,
                revocation_event_id=record.revocation_event_id,
                revocation_seq=record.revocation_seq,
            ).with_digest()


class KeyService:
    """Persistent ML-KEM-768 key management service backed by atomic file storage."""

    def __init__(
        self,
        state_dir: str | Path | None = None,
        grace_period_seconds: int | float | None = None,
    ) -> None:
        self._state_root = resolve_state_dir(state_dir)
        self._store = PersistentKeyStore(state_dir=self._state_root)
        self._grace_period_seconds = (
            _validate_grace_period(grace_period_seconds)
            if grace_period_seconds is not None
            else None
        )

    @property
    def store(self) -> PersistentKeyStore:
        """Return the underlying persistent store."""
        return self._store

    def enrol(self, user: str, device: str, *, now: datetime | None = None) -> dict[str, Any]:
        """Enrol a device for a user and persist a new ML-KEM-768 keypair.

        Raises ValidationError on invalid inputs and DuplicateDeviceError if the
        (user, device) pair already has an active or retiring key.
        """
        validated_user = _validate_identifier(user, "user")
        validated_device = _validate_identifier(device, "device")
        current_time = _normalize_now(now)

        with self._store.locked():
            records = self._store.load_registry()
            _materialize_expired_records(records, current_time)

            for existing in records.values():
                if (
                    existing.user == validated_user
                    and existing.device == validated_device
                    and existing.effective_status(now=current_time)
                    in {STATUS_ACTIVE, STATUS_RETIRING}
                ):
                    raise DuplicateDeviceError(
                        f"Device {validated_device!r} for user {validated_user!r} "
                        f"already has a {existing.status} key ({existing.key_id})."
                    )

            next_version = (
                max(
                    (
                        r.version
                        for r in records.values()
                        if r.user == validated_user and r.device == validated_device
                    ),
                    default=0,
                )
                + 1
            )

            public_key, secret_key = generate_ml_kem_768_keypair()

            key_id = f"mlkem768-{uuid.uuid4().hex}"
            while key_id in records:
                key_id = f"mlkem768-{uuid.uuid4().hex}"

            now_iso = current_time.isoformat()
            public_key_b64 = base64.b64encode(public_key).decode("ascii")
            pk_sha256 = public_key_fingerprint(public_key)

            record = KeyRecord(
                key_id=key_id,
                user=validated_user,
                device=validated_device,
                algorithm=ALGORITHM,
                version=next_version,
                status=STATUS_ACTIVE,
                public_key_b64=public_key_b64,
                public_key_sha256=pk_sha256,
                created_at=now_iso,
                updated_at=now_iso,
                revoked_at=None,
            ).with_digest()

            self._store.save_private_key(key_id, secret_key)
            try:
                records[key_id] = record
                self._store.save_registry(records)
            except Exception:
                self._store.delete_private_key_if_exists(key_id)
                raise

        logger.info(
            "Enrolled %s key_id=%s user=%s device=%s version=%d pk_sha256=%s",
            ALGORITHM,
            record.key_id,
            record.user,
            record.device,
            record.version,
            record.public_key_sha256,
        )
        return record.to_public_dict(now=current_time)

    def get_key_status(self, key_id: str, *, now: datetime | None = None) -> dict[str, Any]:
        """Return public metadata and evaluated lifecycle status for ``key_id``.

        Possible statuses: ``active``, ``retiring``, ``revoked``, ``expired``,
        or ``unknown``.
        """
        validated_key_id = _validate_identifier(key_id, "key_id")
        validate_key_id_filename(validated_key_id)
        current_time = _normalize_now(now)

        with self._store.locked():
            records = self._store.load_registry()

        record = records.get(validated_key_id)
        if record is None:
            return unknown_key_status_dict(validated_key_id)
        return record.to_public_dict(now=current_time)

    def rotate(
        self,
        user: str,
        grace_period_seconds: int | float | None = None,
        *,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Rotate all active ML-KEM-768 keys for ``user`` atomically.

        Previous active keys transition to ``retiring`` with a configurable
        grace period while fresh ``active`` keys with incremented versions are
        persisted without overwriting historical key metadata.
        """
        validated_user = _validate_identifier(user, "user")
        grace_secs = resolve_grace_period_seconds(
            grace_period_seconds
            if grace_period_seconds is not None
            else self._grace_period_seconds
        )
        current_time = _normalize_now(now)
        now_iso = current_time.isoformat()
        grace_until_iso = (current_time + timedelta(seconds=grace_secs)).isoformat()

        written_private_ids: list[str] = []
        retired_records: list[KeyRecord] = []
        new_records: list[KeyRecord] = []

        with self._store.locked():
            records = self._store.load_registry()
            _materialize_expired_records(records, current_time)

            active_keys = sorted(
                (
                    record
                    for record in records.values()
                    if record.user == validated_user and record.status == STATUS_ACTIVE
                ),
                key=lambda item: (item.device, item.version),
            )
            if not active_keys:
                raise NoActiveKeyError(
                    f"No active keys found for user {validated_user!r}."
                )

            try:
                for old_record in active_keys:
                    retired_record = KeyRecord(
                        key_id=old_record.key_id,
                        user=old_record.user,
                        device=old_record.device,
                        algorithm=old_record.algorithm,
                        version=old_record.version,
                        status=STATUS_RETIRING,
                        public_key_b64=old_record.public_key_b64,
                        public_key_sha256=old_record.public_key_sha256,
                        created_at=old_record.created_at,
                        updated_at=now_iso,
                        revoked_at=old_record.revoked_at,
                        retired_at=now_iso,
                        grace_until=grace_until_iso,
                        grace_period_seconds=grace_secs,
                        previous_key_id=old_record.previous_key_id,
                    ).with_digest()

                    next_version = (
                        max(
                            (
                                r.version
                                for r in records.values()
                                if r.user == validated_user and r.device == old_record.device
                            ),
                            default=0,
                        )
                        + 1
                    )

                    public_key, secret_key = generate_ml_kem_768_keypair()
                    new_key_id = f"mlkem768-{uuid.uuid4().hex}"
                    while new_key_id in records:
                        new_key_id = f"mlkem768-{uuid.uuid4().hex}"

                    self._store.save_private_key(new_key_id, secret_key)
                    written_private_ids.append(new_key_id)

                    new_record = KeyRecord(
                        key_id=new_key_id,
                        user=validated_user,
                        device=old_record.device,
                        algorithm=ALGORITHM,
                        version=next_version,
                        status=STATUS_ACTIVE,
                        public_key_b64=base64.b64encode(public_key).decode("ascii"),
                        public_key_sha256=public_key_fingerprint(public_key),
                        created_at=now_iso,
                        updated_at=now_iso,
                        revoked_at=None,
                        previous_key_id=old_record.key_id,
                    ).with_digest()

                    records[old_record.key_id] = retired_record
                    records[new_key_id] = new_record
                    retired_records.append(retired_record)
                    new_records.append(new_record)

                self._store.save_registry(records)
            except Exception:
                for key_id in written_private_ids:
                    self._store.delete_private_key_if_exists(key_id)
                raise

        for old_rec, new_rec in zip(retired_records, new_records):
            logger.info(
                "Rotated %s user=%s device=%s old_key_id=%s new_key_id=%s version=%d grace_until=%s pk_sha256=%s",
                ALGORITHM,
                validated_user,
                new_rec.device,
                old_rec.key_id,
                new_rec.key_id,
                new_rec.version,
                grace_until_iso,
                new_rec.public_key_sha256,
            )

        response: dict[str, Any] = {
            "user": validated_user,
            "rotated_count": len(new_records),
            "grace_period_seconds": grace_secs,
            "grace_until": grace_until_iso,
            "new_keys": [rec.to_public_dict(now=current_time) for rec in new_records],
            "retired_keys": [rec.to_public_dict(now=current_time) for rec in retired_records],
        }
        if len(new_records) == 1:
            response.update(new_records[0].to_public_dict(now=current_time))
        return response

    def revoke(
        self,
        key_id: str,
        *,
        now: datetime | None = None,
        propagate: bool = True,
    ) -> dict[str, Any]:
        """Permanently revoke ``key_id``, record a sequence event, and propagate to nodes."""
        validated_key_id = _validate_identifier(key_id, "key_id")
        validate_key_id_filename(validated_key_id)
        current_time = _normalize_now(now)
        now_iso = current_time.isoformat()

        rev_event: RevocationRecord | None = None
        with self._store.locked():
            records, last_seq, revocations = self._store.load_state()
            record = records.get(validated_key_id)
            if record is None:
                raise KeyNotFoundError(f"Key {validated_key_id!r} was not found.")

            if record.status == STATUS_REVOKED:
                return record.to_public_dict(now=current_time)

            _materialize_expired_records(records, current_time)
            next_seq = last_seq + 1
            event_id = f"rev-{uuid.uuid4().hex}"
            rev_event = RevocationRecord(
                event_id=event_id,
                sequence_number=next_seq,
                key_id=record.key_id,
                user=record.user,
                device=record.device,
                version=record.version,
                revoked_at=now_iso,
                source="keyservice",
            ).with_digest()

            revoked_record = KeyRecord(
                key_id=record.key_id,
                user=record.user,
                device=record.device,
                algorithm=record.algorithm,
                version=record.version,
                status=STATUS_REVOKED,
                public_key_b64=record.public_key_b64,
                public_key_sha256=record.public_key_sha256,
                created_at=record.created_at,
                updated_at=now_iso,
                revoked_at=now_iso,
                retired_at=record.retired_at,
                grace_until=record.grace_until,
                grace_period_seconds=record.grace_period_seconds,
                previous_key_id=record.previous_key_id,
                revocation_event_id=event_id,
                revocation_seq=next_seq,
            ).with_digest()
            records[validated_key_id] = revoked_record
            revocations.append(rev_event)
            self._store.save_registry(
                records,
                last_revocation_seq=next_seq,
                revocations=revocations,
            )

        logger.info(
            "Revoked %s key_id=%s user=%s device=%s version=%d event_id=%s seq=%d",
            ALGORITHM,
            revoked_record.key_id,
            revoked_record.user,
            revoked_record.device,
            revoked_record.version,
            revoked_record.revocation_event_id,
            revoked_record.revocation_seq,
        )

        result = revoked_record.to_public_dict(now=current_time)
        if propagate and rev_event is not None and (self._state_root / "nodes").exists():
            from nodes.cluster import NodeCluster

            result["propagation"] = NodeCluster(
                state_dir=self._state_root
            ).propagate_revocation(rev_event.to_storage_dict(include_digest=True))
        return result

    def is_key_usable(
        self,
        key_id: str,
        *,
        for_new_session: bool = True,
        now: datetime | None = None,
    ) -> bool:
        """Check whether ``key_id`` is accepted for a new or existing session."""
        status_info = self.get_key_status(key_id, now=now)
        if for_new_session:
            return bool(status_info["usable_for_new_session"])
        return bool(status_info["usable_for_existing_session"])

    def get_active_keys(
        self,
        user: str,
        device: str | None = None,
        *,
        now: datetime | None = None,
    ) -> list[dict[str, Any]]:
        """Return public metadata for active keys belonging to ``user``."""
        validated_user = _validate_identifier(user, "user")
        validated_device = (
            _validate_identifier(device, "device") if device is not None else None
        )
        current_time = _normalize_now(now)

        with self._store.locked():
            records = self._store.load_registry()

        matched = [
            record.to_public_dict(now=current_time)
            for record in records.values()
            if record.user == validated_user
            and (validated_device is None or record.device == validated_device)
            and record.effective_status(now=current_time) == STATUS_ACTIVE
        ]
        matched.sort(key=lambda item: (item["device"], item["version"]))
        return matched

    def list_user_keys(
        self,
        user: str,
        *,
        now: datetime | None = None,
    ) -> list[dict[str, Any]]:
        """Return historical and current public key metadata for ``user``."""
        validated_user = _validate_identifier(user, "user")
        current_time = _normalize_now(now)

        with self._store.locked():
            records = self._store.load_registry()

        matched = [
            record.to_public_dict(now=current_time)
            for record in records.values()
            if record.user == validated_user
        ]
        matched.sort(key=lambda item: (item["device"], item["version"]))
        return matched

    def is_revoked(self, user: str, *, now: datetime | None = None) -> bool:
        """Return True when ``user`` has revoked keys and no active usable keys."""
        validated_user = _validate_identifier(user, "user")
        current_time = _normalize_now(now)

        with self._store.locked():
            records = self._store.load_registry()

        user_records = [r for r in records.values() if r.user == validated_user]
        if not user_records:
            return False

        has_active = any(
            r.effective_status(now=current_time) == STATUS_ACTIVE for r in user_records
        )
        has_revoked = any(r.status == STATUS_REVOKED for r in user_records)
        return has_revoked and not has_active

    def get_public_keys(
        self,
        user: str,
        device: str | None = None,
        *,
        now: datetime | None = None,
    ) -> list[dict[str, Any]]:
        """Return usable (active, non-revoked) public key records for ``user``."""
        return self.get_active_keys(user, device=device, now=now)

    def create_backup(self, backup_path: str | Path | None = None) -> dict[str, Any]:
        """Create an integrity-verified backup of persisted keyservice state."""
        return _create_backup(self._store, backup_path=backup_path)

    def verify_backup(self, backup_path: str | Path) -> dict[str, Any]:
        """Validate backup integrity without modifying live state."""
        return _verify_backup(backup_path)

    def restore_backup(self, backup_path: str | Path) -> dict[str, Any]:
        """Verify and atomically restore a backup without reactivating revoked keys."""
        return _restore_backup(self._store, backup_path)

    def recover(self) -> dict[str, Any]:
        """Clean interrupted temp files and verify persisted registry integrity."""
        with self._store.locked():
            records, last_seq, revocations = self._store.load_state()
        return {
            "recovered": True,
            "key_count": len(records),
            "revocation_count": len(revocations),
            "last_revocation_seq": last_seq,
        }


def enrol(user: str, device: str) -> dict[str, Any]:
    """Enrol a device for ``user`` using the configured persistent key store."""
    return KeyService().enrol(user, device)


def get_key_status(key_id: str) -> dict[str, Any]:
    """Retrieve persisted public metadata and lifecycle status for ``key_id``."""
    return KeyService().get_key_status(key_id)


def rotate(user: str, grace_period_seconds: int | float | None = None) -> dict[str, Any]:
    """Rotate active keys for ``user`` and retire prior active keys with grace period."""
    return KeyService().rotate(user, grace_period_seconds=grace_period_seconds)


def revoke(key_id: str) -> dict[str, Any]:
    """Permanently revoke ``key_id`` in the persistent key store."""
    return KeyService().revoke(key_id)


def is_revoked(user: str) -> bool:
    """Return True if ``user`` is revoked (has revoked key(s) and no active keys)."""
    return KeyService().is_revoked(user)


def get_public_keys(user: str) -> list[dict[str, Any]]:
    """Return usable non-revoked public keys for ``user``."""
    return KeyService().get_public_keys(user)


def is_key_usable(key_id: str, *, for_new_session: bool = True) -> bool:
    """Return whether ``key_id`` is accepted for a new or existing session."""
    return KeyService().is_key_usable(key_id, for_new_session=for_new_session)


def get_active_keys(user: str, device: str | None = None) -> list[dict[str, Any]]:
    """Return all currently active public key records for ``user``."""
    return KeyService().get_active_keys(user, device=device)


def list_user_keys(user: str) -> list[dict[str, Any]]:
    """Return all current and historical public key records for ``user``."""
    return KeyService().list_user_keys(user)


def create_backup(backup_path: str | Path | None = None) -> dict[str, Any]:
    """Create an integrity-verified backup of the persistent key store."""
    return KeyService().create_backup(backup_path=backup_path)


def verify_backup(backup_path: str | Path) -> dict[str, Any]:
    """Validate backup integrity and ML-KEM-768 key consistency."""
    return KeyService().verify_backup(backup_path)


def restore_backup(backup_path: str | Path) -> dict[str, Any]:
    """Verify and atomically restore a backup without reactivating revoked keys."""
    return KeyService().restore_backup(backup_path)


def recover() -> dict[str, Any]:
    """Perform crash recovery cleanup and integrity verification on the key store."""
    return KeyService().recover()
