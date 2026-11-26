"""Data models and integrity checksums for the distributed three-node cluster."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .exceptions import NodeIntegrityError, NodeValidationError

DEFAULT_NODE_IDS = ("node-1", "node-2", "node-3")
NODE_SCHEMA_VERSION = 1


def _parse_utc_iso(value: str, field_name: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise NodeIntegrityError(f"Node {field_name} must be a non-empty ISO timestamp.")
    normalized = f"{value[:-1]}+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise NodeIntegrityError(f"Malformed node {field_name}: {value!r}") from exc
    if parsed.tzinfo is None:
        raise NodeIntegrityError(f"Node {field_name} must include timezone info.")
    return parsed.astimezone(timezone.utc)


def compute_event_checksum(payload: dict[str, Any]) -> str:
    """Compute a SHA-256 integrity checksum over revocation event fields.

    Note: This checksum detects accidental corruption or tampering in storage,
    and is NOT a cryptographic signature/authentication mechanism.
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
class RevocationEvent:
    """Immutable revocation event propagated across distributed nodes."""

    event_id: str
    sequence_number: int
    key_id: str
    user: str
    device: str
    version: int
    revoked_at: str
    source: str = "keyservice"
    event_sha256: str = ""

    def with_checksum(self) -> RevocationEvent:
        """Return a copy populated with its SHA-256 integrity checksum."""
        digest = compute_event_checksum(self.to_dict(include_checksum=False))
        return RevocationEvent(
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

    def to_dict(self, include_checksum: bool = True) -> dict[str, Any]:
        """Serialize event fields into a JSON-compatible dictionary."""
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
        if include_checksum:
            data["event_sha256"] = self.event_sha256
        return data

    @classmethod
    def from_dict(cls, data: object) -> RevocationEvent:
        """Deserialize and integrity-check a revocation event dictionary."""
        if not isinstance(data, dict):
            raise NodeValidationError("Revocation event must be a dictionary.")

        required = {
            "event_id",
            "sequence_number",
            "key_id",
            "user",
            "device",
            "version",
            "revoked_at",
            "event_sha256",
        }
        if not required.issubset(data.keys()):
            raise NodeValidationError("Revocation event is missing required fields.")

        for text_field in ("event_id", "key_id", "user", "device"):
            val = data.get(text_field)
            if not isinstance(val, str) or not val.strip():
                raise NodeValidationError(f"Revocation event {text_field!r} must be non-empty.")

        seq = data.get("sequence_number")
        if not isinstance(seq, int) or isinstance(seq, bool) or seq < 1:
            raise NodeValidationError("Revocation event sequence_number must be an integer >= 1.")

        version = data.get("version")
        if not isinstance(version, int) or isinstance(version, bool) or version < 1:
            raise NodeValidationError("Revocation event version must be an integer >= 1.")

        _parse_utc_iso(data["revoked_at"], "event.revoked_at")
        source = data.get("source", "keyservice")
        if not isinstance(source, str) or not source.strip():
            raise NodeValidationError("Revocation event source must be a non-empty string.")

        expected = compute_event_checksum(data)
        if data["event_sha256"] != expected:
            raise NodeIntegrityError(
                f"Revocation event integrity checksum mismatch for {data.get('event_id')!r}."
            )

        return cls(
            event_id=data["event_id"],
            sequence_number=seq,
            key_id=data["key_id"],
            user=data["user"],
            device=data["device"],
            version=version,
            revoked_at=data["revoked_at"],
            source=source,
            event_sha256=data["event_sha256"],
        )


def compute_node_state_checksum(payload: dict[str, Any]) -> str:
    """Compute a SHA-256 integrity checksum over persisted node state."""
    canonical = {
        "schema_version": payload["schema_version"],
        "node_id": payload["node_id"],
        "online": payload["online"],
        "last_applied_seq": payload["last_applied_seq"],
        "keys": payload["keys"],
        "revocations": payload["revocations"],
        "processed_event_ids": payload["processed_event_ids"],
        "sync_metadata": payload["sync_metadata"],
        "updated_at": payload["updated_at"],
    }
    encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


@dataclass
class NodeState:
    """Persistent state snapshot for a single independent node."""

    schema_version: int
    node_id: str
    online: bool
    last_applied_seq: int
    keys: dict[str, dict[str, Any]]
    revocations: dict[str, dict[str, Any]]
    processed_event_ids: list[str]
    sync_metadata: dict[str, Any]
    updated_at: str
    state_sha256: str = ""

    def to_storage_dict(self) -> dict[str, Any]:
        """Serialize state with a freshly computed SHA-256 integrity checksum."""
        body: dict[str, Any] = {
            "schema_version": self.schema_version,
            "node_id": self.node_id,
            "online": self.online,
            "last_applied_seq": self.last_applied_seq,
            "keys": self.keys,
            "revocations": self.revocations,
            "processed_event_ids": self.processed_event_ids,
            "sync_metadata": self.sync_metadata,
            "updated_at": self.updated_at,
        }
        checksum = compute_node_state_checksum(body)
        body["state_sha256"] = checksum
        return body

    @classmethod
    def create_initial(cls, node_id: str, now_iso: str) -> NodeState:
        """Construct a fresh initial state for ``node_id``."""
        return cls(
            schema_version=NODE_SCHEMA_VERSION,
            node_id=node_id,
            online=True,
            last_applied_seq=0,
            keys={},
            revocations={},
            processed_event_ids=[],
            sync_metadata={
                "last_sync_at": None,
                "last_sync_from": [],
                "applied_events": 0,
                "rejected_duplicates": 0,
                "rejected_outdated": 0,
                "recovered_wal_events": 0,
            },
            updated_at=now_iso,
        )

    @classmethod
    def from_storage_dict(cls, data: object, expected_node_id: str) -> NodeState:
        """Deserialize and verify persisted node state."""
        if not isinstance(data, dict):
            raise NodeIntegrityError("Persisted node state must be a JSON object.")

        required = {
            "schema_version",
            "node_id",
            "online",
            "last_applied_seq",
            "keys",
            "revocations",
            "processed_event_ids",
            "sync_metadata",
            "updated_at",
            "state_sha256",
        }
        if not required.issubset(data.keys()):
            raise NodeIntegrityError("Persisted node state is missing required fields.")

        if data["schema_version"] != NODE_SCHEMA_VERSION:
            raise NodeIntegrityError(
                f"Unsupported node schema_version: {data['schema_version']!r}"
            )
        if data["node_id"] != expected_node_id:
            raise NodeIntegrityError(
                f"Node identity mismatch: expected {expected_node_id!r}, got {data['node_id']!r}."
            )
        if not isinstance(data["online"], bool):
            raise NodeIntegrityError("Node 'online' flag must be a boolean.")
        seq = data["last_applied_seq"]
        if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
            raise NodeIntegrityError("Node 'last_applied_seq' must be a non-negative integer.")
        if not isinstance(data["keys"], dict) or not isinstance(data["revocations"], dict):
            raise NodeIntegrityError("Node 'keys' and 'revocations' must be JSON objects.")
        if not isinstance(data["processed_event_ids"], list):
            raise NodeIntegrityError("Node 'processed_event_ids' must be a list.")
        if not isinstance(data["sync_metadata"], dict):
            raise NodeIntegrityError("Node 'sync_metadata' must be a JSON object.")
        _parse_utc_iso(data["updated_at"], "state.updated_at")

        expected_checksum = compute_node_state_checksum(data)
        if data["state_sha256"] != expected_checksum:
            raise NodeIntegrityError(
                f"Node state checksum mismatch for {expected_node_id!r}."
            )

        for key_id, rev_dict in data["revocations"].items():
            rev_event = RevocationEvent.from_dict(rev_dict)
            if rev_event.key_id != key_id:
                raise NodeIntegrityError(
                    f"Node revocation key mismatch for {key_id!r}."
                )
            key_entry = data["keys"].get(key_id)
            if key_entry is None or key_entry.get("status") != "revoked":
                raise NodeIntegrityError(
                    f"Node invariant violated: revoked key {key_id!r} is not marked revoked."
                )

        return cls(
            schema_version=data["schema_version"],
            node_id=data["node_id"],
            online=data["online"],
            last_applied_seq=seq,
            keys=data["keys"],
            revocations=data["revocations"],
            processed_event_ids=list(data["processed_event_ids"]),
            sync_metadata=dict(data["sync_metadata"]),
            updated_at=data["updated_at"],
            state_sha256=data["state_sha256"],
        )
