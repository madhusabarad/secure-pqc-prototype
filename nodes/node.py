"""Independent persistent node implementation with WAL crash recovery and replay protection."""

from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from keyservice.storage import atomic_write_bytes, file_lock, resolve_state_dir

from .exceptions import (
    DuplicateEventError,
    NodeIntegrityError,
    NodeOfflineError,
    NodeValidationError,
    OutdatedEventError,
)
from .models import NodeState, RevocationEvent

logger = logging.getLogger("nodes.node")
logger.addHandler(logging.NullHandler())

_NODE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_KEY_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")


def validate_node_id(node_id: object) -> str:
    """Validate a single-segment node identifier."""
    if not isinstance(node_id, str) or not _NODE_ID_PATTERN.fullmatch(node_id):
        raise NodeValidationError(
            "node_id must be a non-empty alphanumeric/dash/underscore identifier (max 64 chars)."
        )
    return node_id


class Node:
    """An independent key-lifecycle and revocation replica node with atomic persistence."""

    def __init__(self, node_id: str, state_dir: str | Path | None = None) -> None:
        self._node_id = validate_node_id(node_id)
        self._state_root = resolve_state_dir(state_dir)
        self._base_dir = self._state_root / "nodes" / self._node_id
        self._state_path = self._base_dir / "state.json"
        self._wal_path = self._base_dir / "wal.jsonl"
        self._lock_path = self._base_dir / ".node.lock"

    @property
    def node_id(self) -> str:
        """Return this node's identifier."""
        return self._node_id

    @property
    def base_dir(self) -> Path:
        """Return this node's isolated persistent storage directory."""
        return self._base_dir

    @property
    def state_path(self) -> Path:
        """Return the path to this node's persistent state file."""
        return self._state_path

    @property
    def wal_path(self) -> Path:
        """Return the path to this node's write-ahead revocation log."""
        return self._wal_path

    def _cleanup_stale_tmp(self) -> None:
        if not self._base_dir.exists():
            return
        for entry in self._base_dir.iterdir():
            if entry.is_file() and entry.name.startswith(".") and entry.name.endswith(".tmp"):
                try:
                    entry.unlink(missing_ok=True)
                except OSError:
                    pass

    def _save_state_unlocked(self, state: NodeState) -> None:
        state.updated_at = datetime.now(timezone.utc).isoformat()
        encoded = json.dumps(state.to_storage_dict(), indent=2, sort_keys=True).encode("utf-8")
        atomic_write_bytes(self._state_path, encoded, file_mode=0o600, dir_mode=0o700)

    def _append_wal_unlocked(self, event: RevocationEvent) -> None:
        self._base_dir.mkdir(parents=True, exist_ok=True)
        line = (json.dumps(event.to_dict(), sort_keys=True) + "\n").encode("utf-8")
        with open(self._wal_path, "ab") as handle:
            handle.write(line)
            handle.flush()
            os.fsync(handle.fileno())

    @staticmethod
    def _apply_event_to_state(state: NodeState, event: RevocationEvent) -> None:
        existing_key = dict(state.keys.get(event.key_id, {}))
        existing_key.update(
            {
                "key_id": event.key_id,
                "user": event.user,
                "device": event.device,
                "version": event.version,
                "status": "revoked",
                "revoked_at": event.revoked_at,
                "revocation_event_id": event.event_id,
                "revocation_seq": event.sequence_number,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
        )
        state.keys[event.key_id] = existing_key
        state.revocations[event.key_id] = event.to_dict()
        if event.event_id not in state.processed_event_ids:
            state.processed_event_ids.append(event.event_id)
        if event.sequence_number > state.last_applied_seq:
            state.last_applied_seq = event.sequence_number

    def _load_or_recover_unlocked(self) -> NodeState:
        self._cleanup_stale_tmp()
        now_iso = datetime.now(timezone.utc).isoformat()

        if self._state_path.exists():
            try:
                raw_state = json.loads(self._state_path.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise NodeIntegrityError(
                    f"Failed to read or parse state for node {self._node_id!r}."
                ) from exc
            state = NodeState.from_storage_dict(raw_state, expected_node_id=self._node_id)
        else:
            state = NodeState.create_initial(self._node_id, now_iso)
            self._save_state_unlocked(state)

        # Replay any WAL entries committed ahead of the latest state checkpoint.
        if self._wal_path.exists():
            try:
                raw_lines = self._wal_path.read_text(encoding="utf-8").splitlines()
            except (OSError, UnicodeDecodeError) as exc:
                raise NodeIntegrityError(
                    f"Failed to read WAL for node {self._node_id!r}."
                ) from exc

            replayed = 0
            for idx, line in enumerate(raw_lines):
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    raw_event = json.loads(stripped)
                    event = RevocationEvent.from_dict(raw_event)
                except (json.JSONDecodeError, NodeValidationError, NodeIntegrityError) as exc:
                    # Tolerate a torn trailing line if a crash interrupted an append.
                    if idx == len(raw_lines) - 1:
                        break
                    raise NodeIntegrityError(
                        f"Corrupted WAL entry at line {idx + 1} for node {self._node_id!r}."
                    ) from exc

                if (
                    event.event_id not in state.processed_event_ids
                    and event.sequence_number > state.last_applied_seq
                ):
                    self._apply_event_to_state(state, event)
                    state.sync_metadata["applied_events"] = (
                        int(state.sync_metadata.get("applied_events", 0)) + 1
                    )
                    replayed += 1

            if replayed > 0:
                state.sync_metadata["recovered_wal_events"] = (
                    int(state.sync_metadata.get("recovered_wal_events", 0)) + replayed
                )
                self._save_state_unlocked(state)

        return state

    def initialize(self) -> dict[str, Any]:
        """Ensure persistent node state exists and run crash recovery if needed."""
        with file_lock(self._lock_path):
            state = self._load_or_recover_unlocked()
            return state.to_storage_dict()

    def recover(self) -> dict[str, Any]:
        """Recover persistent node state and replay uncommitted WAL revocations."""
        return self.initialize()

    def is_online(self) -> bool:
        """Return whether this node is currently marked online."""
        with file_lock(self._lock_path):
            state = self._load_or_recover_unlocked()
            return state.online

    def set_online(self, online: bool) -> dict[str, Any]:
        """Persist this node's online/offline availability state."""
        if not isinstance(online, bool):
            raise NodeValidationError("online must be a boolean.")
        with file_lock(self._lock_path):
            state = self._load_or_recover_unlocked()
            state.online = online
            self._save_state_unlocked(state)
            return state.to_storage_dict()

    def apply_revocation_event(self, event: RevocationEvent | dict[str, Any]) -> dict[str, Any]:
        """Validate and apply a revocation event with replay and sequence protection."""
        parsed = event if isinstance(event, RevocationEvent) else RevocationEvent.from_dict(event)
        # Re-verify checksum even if caller supplied a RevocationEvent instance.
        verified = RevocationEvent.from_dict(parsed.to_dict())

        with file_lock(self._lock_path):
            state = self._load_or_recover_unlocked()
            if not state.online:
                raise NodeOfflineError(
                    f"Node {self._node_id!r} is offline and cannot receive events."
                )

            if verified.event_id in state.processed_event_ids:
                state.sync_metadata["rejected_duplicates"] = (
                    int(state.sync_metadata.get("rejected_duplicates", 0)) + 1
                )
                self._save_state_unlocked(state)
                raise DuplicateEventError(
                    f"Node {self._node_id!r} rejected duplicate event {verified.event_id!r}."
                )

            if verified.sequence_number <= state.last_applied_seq:
                state.sync_metadata["rejected_outdated"] = (
                    int(state.sync_metadata.get("rejected_outdated", 0)) + 1
                )
                self._save_state_unlocked(state)
                raise OutdatedEventError(
                    f"Node {self._node_id!r} rejected outdated sequence "
                    f"{verified.sequence_number} (last_applied_seq={state.last_applied_seq})."
                )

            self._append_wal_unlocked(verified)
            self._apply_event_to_state(state, verified)
            state.sync_metadata["applied_events"] = (
                int(state.sync_metadata.get("applied_events", 0)) + 1
            )
            self._save_state_unlocked(state)

        logger.info(
            "Node %s applied revocation seq=%d event_id=%s key_id=%s",
            self._node_id,
            verified.sequence_number,
            verified.event_id,
            verified.key_id,
        )
        return {
            "node_id": self._node_id,
            "applied": True,
            "event_id": verified.event_id,
            "sequence_number": verified.sequence_number,
            "key_id": verified.key_id,
            "last_applied_seq": state.last_applied_seq,
        }

    def sync_key_metadata(
        self,
        key_entries: dict[str, dict[str, Any]],
        *,
        source: str = "keyservice",
    ) -> dict[str, Any]:
        """Synchronize non-secret key lifecycle metadata without un-revoking revoked keys."""
        if not isinstance(key_entries, dict):
            raise NodeValidationError("key_entries must be a dictionary.")

        with file_lock(self._lock_path):
            state = self._load_or_recover_unlocked()
            if not state.online:
                raise NodeOfflineError(f"Node {self._node_id!r} is offline.")

            updated_count = 0
            for key_id, entry in key_entries.items():
                if not isinstance(key_id, str) or not _KEY_ID_PATTERN.fullmatch(key_id):
                    raise NodeValidationError(f"Invalid key_id in sync metadata: {key_id!r}")
                if not isinstance(entry, dict):
                    raise NodeValidationError(f"Metadata entry for {key_id!r} must be a dict.")

                existing = state.keys.get(key_id)
                if key_id in state.revocations or (
                    existing is not None and existing.get("status") == "revoked"
                ):
                    # Monotonic revocation invariant: never allow revoked keys to become valid again.
                    continue

                sanitized = {
                    "key_id": key_id,
                    "user": entry.get("user"),
                    "device": entry.get("device"),
                    "version": entry.get("version"),
                    "status": entry.get("status"),
                    "public_key_sha256": entry.get("public_key_sha256"),
                    "grace_until": entry.get("grace_until"),
                    "revoked_at": entry.get("revoked_at"),
                    "revocation_event_id": entry.get("revocation_event_id"),
                    "revocation_seq": entry.get("revocation_seq"),
                    "updated_at": entry.get("updated_at"),
                }
                if existing != sanitized:
                    state.keys[key_id] = sanitized
                    updated_count += 1

            state.sync_metadata["last_sync_at"] = datetime.now(timezone.utc).isoformat()
            last_from = list(state.sync_metadata.get("last_sync_from", []))
            if source not in last_from:
                last_from.append(source)
            state.sync_metadata["last_sync_from"] = last_from
            self._save_state_unlocked(state)

            return {
                "node_id": self._node_id,
                "synced_keys": updated_count,
                "last_applied_seq": state.last_applied_seq,
            }

    def get_key_status(self, key_id: str) -> dict[str, Any]:
        """Retrieve a key's local lifecycle status on this node."""
        if not isinstance(key_id, str) or not _KEY_ID_PATTERN.fullmatch(key_id):
            raise NodeValidationError("key_id must be an alphanumeric/dash/underscore identifier.")

        with file_lock(self._lock_path):
            state = self._load_or_recover_unlocked()

        if key_id in state.revocations:
            entry = dict(state.keys.get(key_id, {}))
            entry["status"] = "revoked"
            entry["node_id"] = self._node_id
            return entry

        entry = state.keys.get(key_id)
        if entry is None:
            return {"node_id": self._node_id, "key_id": key_id, "status": "unknown"}

        result = dict(entry)
        result["node_id"] = self._node_id
        return result

    def is_key_revoked(self, key_id: str) -> bool:
        """Return True if ``key_id`` is revoked on this node."""
        return self.get_key_status(key_id).get("status") == "revoked"

    def get_state(self) -> dict[str, Any]:
        """Return a verified snapshot of this node's persistent state."""
        with file_lock(self._lock_path):
            state = self._load_or_recover_unlocked()
            return state.to_storage_dict()
