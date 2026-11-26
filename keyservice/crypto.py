"""ML-KEM-768 cryptographic primitives backed exclusively by pqcrypto==0.4.0."""

from __future__ import annotations

import hashlib

from pqcrypto.kem import ml_kem_768

from .exceptions import KeyServiceError

ML_KEM_PUBLIC_KEY_SIZE = ml_kem_768.PUBLIC_KEY_SIZE
ML_KEM_SECRET_KEY_SIZE = ml_kem_768.SECRET_KEY_SIZE
ML_KEM_ALGORITHM_NAME = ml_kem_768.ALGORITHM


def generate_ml_kem_768_keypair() -> tuple[bytes, bytes]:
    """Generate an ML-KEM-768 (public_key, secret_key) pair using pqcrypto."""
    public_key, secret_key = ml_kem_768.generate_keypair()
    if len(public_key) != ML_KEM_PUBLIC_KEY_SIZE or len(secret_key) != ML_KEM_SECRET_KEY_SIZE:
        raise KeyServiceError("Generated ML-KEM-768 keypair did not match expected key sizes.")
    return public_key, secret_key


def public_key_fingerprint(public_key: bytes) -> str:
    """Return the SHA-256 hex digest of an ML-KEM-768 public key."""
    return hashlib.sha256(public_key).hexdigest()
