"""Distributed three-node key revocation and synchronization package."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .cluster import NodeCluster
from .exceptions import (
    DuplicateEventError,
    NodeError,
    NodeIntegrityError,
    NodeNotFoundError,
    NodeOfflineError,
    NodeValidationError,
    OutdatedEventError,
)
from .models import DEFAULT_NODE_IDS, NODE_SCHEMA_VERSION, NodeState, RevocationEvent
from .node import Node


def initialize_cluster(
    state_dir: str | Path | None = None,
    *,
    bootstrap_from_keyservice: bool = True,
) -> dict[str, Any]:
    """Initialize the default three-node cluster."""
    return NodeCluster(state_dir=state_dir).initialize_nodes(
        bootstrap_from_keyservice=bootstrap_from_keyservice
    )


def propagate_revocation(
    event: RevocationEvent | dict[str, Any],
    state_dir: str | Path | None = None,
) -> dict[str, Any]:
    """Propagate a revocation event across all available nodes."""
    return NodeCluster(state_dir=state_dir).propagate_revocation(event)


def sync_nodes(state_dir: str | Path | None = None) -> dict[str, Any]:
    """Synchronize all online nodes in the cluster."""
    return NodeCluster(state_dir=state_dir).sync_all()


def get_cluster_status(state_dir: str | Path | None = None) -> dict[str, Any]:
    """Return status and consistency metrics for all three nodes."""
    return NodeCluster(state_dir=state_dir).get_cluster_status()


__all__ = [
    "DEFAULT_NODE_IDS",
    "DuplicateEventError",
    "NODE_SCHEMA_VERSION",
    "Node",
    "NodeCluster",
    "NodeError",
    "NodeIntegrityError",
    "NodeNotFoundError",
    "NodeOfflineError",
    "NodeState",
    "NodeValidationError",
    "OutdatedEventError",
    "RevocationEvent",
    "get_cluster_status",
    "initialize_cluster",
    "propagate_revocation",
    "sync_nodes",
]
