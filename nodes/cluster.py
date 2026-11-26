"""Three-node cluster manager for revocation propagation, synchronization, and recovery."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Iterable

from keyservice.exceptions import StorageIntegrityError
from keyservice.storage import PersistentKeyStore, resolve_state_dir

from .exceptions import (
    DuplicateEventError,
    NodeNotFoundError,
    NodeOfflineError,
    NodeValidationError,
    OutdatedEventError,
)
from .models import DEFAULT_NODE_IDS, RevocationEvent
from .node import Node, validate_node_id

logger = logging.getLogger("nodes.cluster")
logger.addHandler(logging.NullHandler())


class NodeCluster:
    """Manages three independent persistent nodes and revocation synchronization."""

    def __init__(
        self,
        node_ids: Iterable[str] = DEFAULT_NODE_IDS,
        state_dir: str | Path | None = None,
    ) -> None:
        validated_ids = tuple(validate_node_id(nid) for nid in node_ids)
        if len(validated_ids) < 3 or len(set(validated_ids)) != len(validated_ids):
            raise NodeValidationError(
                "NodeCluster requires at least 3 distinct valid node identifiers."
            )
        self._node_ids = validated_ids
        self._state_dir = resolve_state_dir(state_dir)
        self._nodes = {
            nid: Node(nid, state_dir=self._state_dir) for nid in self._node_ids
        }

    @property
    def node_ids(self) -> tuple[str, ...]:
        """Return ordered tuple of managed node IDs."""
        return self._node_ids

    def get_node(self, node_id: str) -> Node:
        """Return the ``Node`` instance for ``node_id``."""
        validated = validate_node_id(node_id)
        node = self._nodes.get(validated)
        if node is None:
            raise NodeNotFoundError(f"Unknown cluster node: {node_id!r}")
        return node

    def initialize_nodes(self, *, bootstrap_from_keyservice: bool = True) -> dict[str, Any]:
        """Initialize all three nodes and optionally bootstrap existing keyservice state."""
        initialized: dict[str, dict[str, Any]] = {}
        for nid, node in self._nodes.items():
            initialized[nid] = node.initialize()

        sync_report: dict[str, Any] | None = None
        if bootstrap_from_keyservice:
            sync_report = self.sync_all()

        return {
            "node_ids": list(self._node_ids),
            "nodes": initialized,
            "sync_report": sync_report,
        }

    def set_node_online(self, node_id: str, online: bool) -> dict[str, Any]:
        """Set a node's persistent online/offline availability flag."""
        return self.get_node(node_id).set_online(online)

    def _load_keyservice_snapshot(
        self,
    ) -> tuple[dict[str, dict[str, Any]], dict[str, RevocationEvent]]:
        key_store = PersistentKeyStore(state_dir=self._state_dir)
        if not key_store.registry_path.exists():
            return {}, {}

        try:
            with key_store.locked():
                records, _, revocations = key_store.load_state()
        except StorageIntegrityError:
            return {}, {}

        key_entries = {
            kid: {
                "key_id": rec.key_id,
                "user": rec.user,
                "device": rec.device,
                "version": rec.version,
                "status": rec.effective_status(),
                "public_key_sha256": rec.public_key_sha256,
                "grace_until": rec.grace_until,
                "revoked_at": rec.revoked_at,
                "revocation_event_id": rec.revocation_event_id,
                "revocation_seq": rec.revocation_seq,
                "updated_at": rec.updated_at,
            }
            for kid, rec in records.items()
        }
        rev_events = {
            rev.event_id: RevocationEvent.from_dict(rev.to_storage_dict(include_digest=True))
            for rev in revocations
        }
        return key_entries, rev_events

    def propagate_revocation(
        self,
        event: RevocationEvent | dict[str, Any],
    ) -> dict[str, Any]:
        """Propagate a revocation event to all available nodes in the cluster."""
        verified = (
            RevocationEvent.from_dict(event.to_dict())
            if isinstance(event, RevocationEvent)
            else RevocationEvent.from_dict(event)
        )

        applied_nodes: list[str] = []
        offline_nodes: list[str] = []
        rejected_nodes: dict[str, str] = {}

        for nid, node in self._nodes.items():
            try:
                node.apply_revocation_event(verified)
                applied_nodes.append(nid)
            except NodeOfflineError:
                offline_nodes.append(nid)
            except DuplicateEventError:
                rejected_nodes[nid] = "duplicate_event"
            except OutdatedEventError:
                rejected_nodes[nid] = "outdated_event"

        logger.info(
            "Propagated revocation event_id=%s seq=%d applied=%s offline=%s rejected=%s",
            verified.event_id,
            verified.sequence_number,
            applied_nodes,
            offline_nodes,
            list(rejected_nodes.keys()),
        )
        return {
            "event_id": verified.event_id,
            "sequence_number": verified.sequence_number,
            "key_id": verified.key_id,
            "applied_nodes": applied_nodes,
            "offline_nodes": offline_nodes,
            "rejected_nodes": rejected_nodes,
        }

    def _collect_authoritative_state(
        self,
    ) -> tuple[dict[str, dict[str, Any]], list[RevocationEvent], list[str]]:
        ks_keys, ks_events = self._load_keyservice_snapshot()
        merged_keys: dict[str, dict[str, Any]] = dict(ks_keys)
        merged_events: dict[str, RevocationEvent] = dict(ks_events)
        sources: list[str] = ["keyservice"] if (ks_keys or ks_events) else []

        for nid, node in self._nodes.items():
            state = node.get_state()
            if not state["online"]:
                continue
            sources.append(nid)
            for kid, entry in state["keys"].items():
                current = merged_keys.get(kid)
                if current is None:
                    merged_keys[kid] = dict(entry)
                elif entry.get("status") == "revoked" and current.get("status") != "revoked":
                    merged_keys[kid] = dict(entry)
            for raw_ev in state["revocations"].values():
                ev = RevocationEvent.from_dict(raw_ev)
                merged_events.setdefault(ev.event_id, ev)

        ordered_events = sorted(
            merged_events.values(),
            key=lambda item: (item.sequence_number, item.event_id),
        )
        return merged_keys, ordered_events, sources

    def sync_node(self, node_id: str) -> dict[str, Any]:
        """Synchronize missed key metadata and revocations onto ``node_id``."""
        target = self.get_node(node_id)
        target_state = target.get_state()
        if not target_state["online"]:
            return {
                "node_id": target.node_id,
                "status": "offline",
                "applied_revocations": 0,
                "last_applied_seq": target_state["last_applied_seq"],
            }

        merged_keys, ordered_events, sources = self._collect_authoritative_state()
        peer_sources = [s for s in sources if s != target.node_id]
        source_label = ",".join(peer_sources) if peer_sources else "self"

        # Apply non-secret metadata first (never un-revoking already-revoked keys).
        target.sync_key_metadata(merged_keys, source=source_label)

        applied = 0
        for ev in ordered_events:
            current_state = target.get_state()
            if (
                ev.event_id in current_state["processed_event_ids"]
                or ev.sequence_number <= current_state["last_applied_seq"]
            ):
                continue
            try:
                target.apply_revocation_event(ev)
                applied += 1
            except (DuplicateEventError, OutdatedEventError):
                continue

        final_state = target.get_state()
        return {
            "node_id": target.node_id,
            "status": "synced",
            "applied_revocations": applied,
            "last_applied_seq": final_state["last_applied_seq"],
        }

    def sync_all(self) -> dict[str, Any]:
        """Synchronize all online nodes in the cluster."""
        results = {nid: self.sync_node(nid) for nid in self._node_ids}
        return {
            "results": results,
            "consistent": self.is_consistent(),
        }

    def recover_node(self, node_id: str) -> dict[str, Any]:
        """Recover ``node_id`` from disk/WAL and catch up from peers if online."""
        node = self.get_node(node_id)
        recovered_state = node.recover()
        if recovered_state["online"]:
            sync_result = self.sync_node(node_id)
        else:
            sync_result = {
                "node_id": node.node_id,
                "status": "offline",
                "applied_revocations": 0,
                "last_applied_seq": recovered_state["last_applied_seq"],
            }
        return {
            "node_id": node.node_id,
            "recovered": True,
            "sync": sync_result,
            "state": node.get_state(),
        }

    def is_consistent(self) -> bool:
        """Return True if all online nodes agree on sequence number and revoked keys."""
        online_states = [
            state
            for state in (node.get_state() for node in self._nodes.values())
            if state["online"]
        ]
        if len(online_states) <= 1:
            return True

        first_seq = online_states[0]["last_applied_seq"]
        first_revoked = set(online_states[0]["revocations"].keys())
        return all(
            st["last_applied_seq"] == first_seq and set(st["revocations"].keys()) == first_revoked
            for st in online_states[1:]
        )

    def get_cluster_status(self) -> dict[str, Any]:
        """Return non-secret status across all three nodes."""
        nodes_summary: dict[str, Any] = {}
        for nid, node in self._nodes.items():
            st = node.get_state()
            nodes_summary[nid] = {
                "online": st["online"],
                "last_applied_seq": st["last_applied_seq"],
                "key_count": len(st["keys"]),
                "revoked_count": len(st["revocations"]),
                "revoked_key_ids": sorted(st["revocations"].keys()),
                "sync_metadata": st["sync_metadata"],
            }
        return {
            "node_ids": list(self._node_ids),
            "consistent": self.is_consistent(),
            "nodes": nodes_summary,
        }
