"""Domain exceptions for the distributed three-node key management system."""


class NodeError(Exception):
    """Base exception for all distributed node failures."""


class NodeValidationError(NodeError, ValueError):
    """Raised when node identifiers, state directories, or events are invalid."""


class NodeNotFoundError(NodeError):
    """Raised when a requested node ID is not part of the cluster."""


class NodeOfflineError(NodeError):
    """Raised when attempting to deliver an event to an offline node."""


class DuplicateEventError(NodeError):
    """Raised when a node receives a revocation event ID it has already processed."""


class OutdatedEventError(NodeError):
    """Raised when a node receives an event with a stale or outdated sequence number."""


class NodeIntegrityError(NodeError):
    """Raised when persisted node state or WAL records fail integrity verification."""
