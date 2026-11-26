"""Data models, status constants, and record integrity helpers for keyservice."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .exceptions import StorageIntegrityError

ALGORITHM = "ML-KEM-768"
SCHEMA_VERSION = 1
DEFAULT_GRACE_PERIOD_SECONDS = 300.0

STATUS_ACTIVE = "active"
STATUS_RETIRING = "retiring"
STATUS_REVOKED = "revoked"
STATUS_EXPIRED = "expired"
STATUS_UNKNOWN = "unknown"

STORED_STATUSES = frozenset(
    {STATUS_ACTIVE, STATUS_RETIRING, STATUS_REVOKED, STATUS_EXPIRED}
)
VALID_STATUSES = frozenset(
    {STATUS_ACTIVE, STATUS_RETIRING, STATUS_REVOKED, STATUS_EXPIRED, STATUS_UNKNOWN}
)

_OPTIONAL_DIGEST_FIELDS = (
    "retired_at",
    "grace_until",
    "grace_period_seconds",
    "previous_key_id",
    "revocation_event_id",
    "revocation_seq",
)


def parse_utc_timestamp(value: str, field_name: str = "timestamp") -> datetime:
    """Parse an ISO-8601 timestamp and normalize it to UTC."""
    if not isinstance(value, str) or not value:
        raise StorageIntegrityError(f"Persisted {field_name} must be a non-empty string.")
    normalized = f"{value[:-1]}+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise StorageIntegrityError(f"Persisted {field_name} is malformed: {value!r}") from exc
    if parsed.tzinfo is None:
        raise StorageIntegrityError(f"Persisted {field_name} must include timezone info.")
    return parsed.astimezone(timezone.utc)


def unknown_key_status_dict(key_id: str) -> dict[str, Any]:
    """Return a non-secret status payload for an unknown key ID."""
    return {
        "key_id": key_id,
        "user": None,
        "device": None,
        "algorithm": ALGORITHM,
        "version": None,
        "status": STATUS_UNKNOWN,
        "public_key": None,
        "public_key_sha256": None,
        "created_at": None,
        "updated_at": None,
        "retired_at": None,
        "grace_until": None,
        "grace_period_seconds": None,
        "revoked_at": None,
        "revocation_event_id": None,
        "revocation_seq": None,
        "previous_key_id": None,
        "usable_for_new_session": False,
        "usable_for_existing_session": False,
    }


def compute_record_digest(payload: dict[str, Any]) -> str:
    """Compute a deterministic SHA-256 hex digest over public key record metadata."""
    canonical_fields: dict[str, Any] = {
        "key_id": payload["key_id"],
        "user": payload["user"],
        "device": payload["device"],
        "algorithm": payload["algorithm"],
        "version": payload["version"],
        "status": payload["status"],
        "public_key_b64": payload["public_key_b64"],
        "public_key_sha256": payload["public_key_sha256"],
        "created_at": payload["created_at"],
        "updated_at": payload["updated_at"],
        "revoked_at": payload.get("revoked_at"),
    }
    for field in _OPTIONAL_DIGEST_FIELDS:
        if field in payload:
            canonical_fields[field] = payload[field]
    encoded = json.dumps(canonical_fields, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class KeyRecord:
    """Public metadata record for an enrolled ML-KEM-768 device key.

    Private key material is never stored on KeyRecord instances.
    """

    key_id: str
    user: str
    device: str
    algorithm: str
    version: int
    status: str
    public_key_b64: str
    public_key_sha256: str
    created_at: str
    updated_at: str
    revoked_at: str | None = None
    retired_at: str | None = None
    grace_until: str | None = None
    grace_period_seconds: float | None = None
    previous_key_id: str | None = None
    revocation_event_id: str | None = None
    revocation_seq: int | None = None
    record_sha256: str = ""

    def effective_status(self, now: datetime | None = None) -> str:
        """Evaluate the key's effective lifecycle status at ``now`` (UTC)."""
        if self.status == STATUS_REVOKED:
            return STATUS_REVOKED
        if self.status == STATUS_EXPIRED:
            return STATUS_EXPIRED
        if self.status == STATUS_ACTIVE:
            return STATUS_ACTIVE
        if self.status == STATUS_RETIRING:
            if self.grace_until is None:
                return STATUS_EXPIRED
            current = (
                datetime.now(timezone.utc)
                if now is None
                else (now.replace(tzinfo=timezone.utc) if now.tzinfo is None else now.astimezone(timezone.utc))
            )
            deadline = parse_utc_timestamp(self.grace_until, "grace_until")
            return STATUS_RETIRING if current < deadline else STATUS_EXPIRED
        return STATUS_UNKNOWN

    def is_usable_for_new_session(self, now: datetime | None = None) -> bool:
        """Only active keys may be used to establish new sessions."""
        return self.effective_status(now=now) == STATUS_ACTIVE

    def is_usable_for_existing_session(self, now: datetime | None = None) -> bool:
        """Active keys and unexpired retiring keys may finish existing sessions."""
        return self.effective_status(now=now) in {STATUS_ACTIVE, STATUS_RETIRING}

    def with_digest(self) -> KeyRecord:
        """Return a copy of this record populated with its integrity digest."""
        digest = compute_record_digest(self.to_storage_dict(include_digest=False))
        return KeyRecord(
            key_id=self.key_id,
            user=self.user,
            device=self.device,
            algorithm=self.algorithm,
            version=self.version,
            status=self.status,
            public_key_b64=self.public_key_b64,
            public_key_sha256=self.public_key_sha256,
            created_at=self.created_at,
            updated_at=self.updated_at,
            revoked_at=self.revoked_at,
            retired_at=self.retired_at,
            grace_until=self.grace_until,
            grace_period_seconds=self.grace_period_seconds,
            previous_key_id=self.previous_key_id,
            revocation_event_id=self.revocation_event_id,
            revocation_seq=self.revocation_seq,
            record_sha256=digest,
        )

    def to_storage_dict(self, include_digest: bool = True) -> dict[str, Any]:
        """Serialize record fields for persistent JSON storage."""
        data: dict[str, Any] = {
            "key_id": self.key_id,
            "user": self.user,
            "device": self.device,
            "algorithm": self.algorithm,
            "version": self.version,
            "status": self.status,
            "public_key_b64": self.public_key_b64,
            "public_key_sha256": self.public_key_sha256,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "revoked_at": self.revoked_at,
            "retired_at": self.retired_at,
            "grace_until": self.grace_until,
            "grace_period_seconds": self.grace_period_seconds,
            "previous_key_id": self.previous_key_id,
            "revocation_event_id": self.revocation_event_id,
            "revocation_seq": self.revocation_seq,
        }
        if include_digest:
            data["record_sha256"] = self.record_sha256
        return data

    def to_public_dict(self, now: datetime | None = None) -> dict[str, Any]:
        """Return a public-safe dictionary suitable for API responses."""
        eff_status = self.effective_status(now=now)
        return {
            "key_id": self.key_id,
            "user": self.user,
            "device": self.device,
            "algorithm": self.algorithm,
            "version": self.version,
            "status": eff_status,
            "public_key": self.public_key_b64,
            "public_key_sha256": self.public_key_sha256,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "retired_at": self.retired_at,
            "grace_until": self.grace_until,
            "grace_period_seconds": self.grace_period_seconds,
            "revoked_at": self.revoked_at,
            "revocation_event_id": self.revocation_event_id,
            "revocation_seq": self.revocation_seq,
            "previous_key_id": self.previous_key_id,
            "usable_for_new_session": eff_status == STATUS_ACTIVE,
            "usable_for_existing_session": eff_status in {STATUS_ACTIVE, STATUS_RETIRING},
        }

    @classmethod
    def from_storage_dict(cls, data: dict[str, Any]) -> KeyRecord:
        """Deserialize and verify a KeyRecord loaded from persistent storage."""
        required = {
            "key_id",
            "user",
            "device",
            "algorithm",
            "version",
            "status",
            "public_key_b64",
            "public_key_sha256",
            "created_at",
            "updated_at",
            "record_sha256",
        }
        if not isinstance(data, dict) or not required.issubset(data.keys()):
            raise StorageIntegrityError("Persisted key record is missing required fields.")

        status = data["status"]
        if status not in STORED_STATUSES:
            raise StorageIntegrityError(f"Persisted key record has invalid status: {status!r}")

        version = data["version"]
        if not isinstance(version, int) or isinstance(version, bool) or version < 1:
            raise StorageIntegrityError("Persisted key record has invalid version.")

        parse_utc_timestamp(data["created_at"], "created_at")
        parse_utc_timestamp(data["updated_at"], "updated_at")
        if data.get("revoked_at") is not None:
            parse_utc_timestamp(data["revoked_at"], "revoked_at")
        if data.get("retired_at") is not None:
            parse_utc_timestamp(data["retired_at"], "retired_at")
        if data.get("grace_until") is not None:
            parse_utc_timestamp(data["grace_until"], "grace_until")

        grace_secs = data.get("grace_period_seconds")
        if grace_secs is not None:
            if (
                not isinstance(grace_secs, (int, float))
                or isinstance(grace_secs, bool)
                or grace_secs < 0
            ):
                raise StorageIntegrityError("Persisted key record has invalid grace_period_seconds.")

        rev_seq = data.get("revocation_seq")
        if rev_seq is not None:
            if not isinstance(rev_seq, int) or isinstance(rev_seq, bool) or rev_seq < 1:
                raise StorageIntegrityError("Persisted key record has invalid revocation_seq.")

        expected_digest = compute_record_digest(data)
        if data["record_sha256"] != expected_digest:
            raise StorageIntegrityError(
                f"Integrity check failed for key record {data.get('key_id', '<unknown>')!r}."
            )

        return cls(
            key_id=data["key_id"],
            user=data["user"],
            device=data["device"],
            algorithm=data["algorithm"],
            version=version,
            status=status,
            public_key_b64=data["public_key_b64"],
            public_key_sha256=data["public_key_sha256"],
            created_at=data["created_at"],
            updated_at=data["updated_at"],
            revoked_at=data.get("revoked_at"),
            retired_at=data.get("retired_at"),
            grace_until=data.get("grace_until"),
            grace_period_seconds=float(grace_secs) if grace_secs is not None else None,
            previous_key_id=data.get("previous_key_id"),
            revocation_event_id=data.get("revocation_event_id"),
            revocation_seq=rev_seq,
            record_sha256=data["record_sha256"],
        )


def compute_revocation_digest(payload: dict[str, Any]) -> str:
    """Compute a SHA-256 integrity checksum over revocation event fields.

    Note: This is an integrity checksum, not a cryptographic signature.
    """
    canonical = {
        "event_id": payload["event_id"],
        "sequence_number": payload["sequence_number"],
        "key_id": payload["key_id"],
        "user": payload["user"],
        "device": payload["device"],
        "version": payload["version"],
        "revoked_at": payload["revoked_at"],
        "source": payload.get("source", "keyservice"),
    }
    encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class RevocationRecord:
    """Persistent revocation event record with monotonic sequence number."""

    event_id: str
    sequence_number: int
    key_id: str
    user: str
    device: str
    version: int
    revoked_at: str
    source: str = "keyservice"
    event_sha256: str = ""

    def with_digest(self) -> RevocationRecord:
        """Return a copy populated with its integrity checksum."""
        digest = compute_revocation_digest(self.to_storage_dict(include_digest=False))
        return RevocationRecord(
            event_id=self.event_id,
            sequence_number=self.sequence_number,
            key_id=self.key_id,
            user=self.user,
            device=self.device,
            version=self.version,
            revoked_at=self.revoked_at,
            source=self.source,
            event_sha256=digest,
        )

    def to_storage_dict(self, include_digest: bool = True) -> dict[str, Any]:
        """Serialize revocation event fields."""
        data: dict[str, Any] = {
            "event_id": self.event_id,
            "sequence_number": self.sequence_number,
            "key_id": self.key_id,
            "user": self.user,
            "device": self.device,
            "version": self.version,
            "revoked_at": self.revoked_at,
            "source": self.source,
        }
        if include_digest:
            data["event_sha256"] = self.event_sha256
        return data

    @classmethod
    def from_storage_dict(cls, data: dict[str, Any]) -> RevocationRecord:
        """Deserialize and verify a RevocationRecord."""
        required = {
            "event_id",
            "sequence_number",
            "key_id",
            "user",
            "device",
            "version",
            "revoked_at",
            "source",
            "event_sha256",
        }
        if not isinstance(data, dict) or not required.issubset(data.keys()):
            raise StorageIntegrityError("Revocation record is missing required fields.")

        seq = data["sequence_number"]
        if not isinstance(seq, int) or isinstance(seq, bool) or seq < 1:
            raise StorageIntegrityError("Revocation record has invalid sequence_number.")

        version = data["version"]
        if not isinstance(version, int) or isinstance(version, bool) or version < 1:
            raise StorageIntegrityError("Revocation record has invalid version.")

        parse_utc_timestamp(data["revoked_at"], "revoked_at")
        expected = compute_revocation_digest(data)
        if data["event_sha256"] != expected:
            raise StorageIntegrityError(
                f"Integrity check failed for revocation event {data.get('event_id', '<unknown>')!r}."
            )

        return cls(
            event_id=data["event_id"],
            sequence_number=seq,
            key_id=data["key_id"],
            user=data["user"],
            device=data["device"],
            version=version,
            revoked_at=data["revoked_at"],
            source=data["source"],
            event_sha256=data["event_sha256"],
        )
