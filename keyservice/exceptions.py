"""Domain exceptions for the post-quantum key management service."""


class KeyServiceError(Exception):
    """Base exception for all keyservice failures."""


class ValidationError(KeyServiceError, ValueError):
    """Raised when caller-supplied parameters fail validation."""


class DuplicateDeviceError(KeyServiceError):
    """Raised when enrolling a device that already holds an active or retiring key."""


class KeyNotFoundError(KeyServiceError):
    """Raised when a requested key ID or active user key does not exist."""


class NoActiveKeyError(KeyNotFoundError):
    """Raised when a user has no active keys available to rotate."""


class StorageIntegrityError(KeyServiceError):
    """Raised when persisted key store state is malformed or fails integrity checks."""


class BackupIntegrityError(StorageIntegrityError):
    """Raised when a key backup is corrupted, tampered with, or unsafe to restore."""
