"""Protected read KEM encapsulation and HMAC proof helper."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac

from pqcrypto.kem.ml_kem_768 import PUBLIC_KEY_SIZE, encrypt


def protected_read(public_key_b64: str, challenge: str, body: str) -> dict[str, str]:
    """Encapsulate a shared secret to an ML-KEM-768 public key and sign challenge+body via HMAC-SHA256.

    Args:
        public_key_b64: Base64-encoded ML-KEM-768 public key.
        challenge: Challenge string.
        body: Body string.

    Returns:
        Dictionary containing base64-encoded ``ciphertext`` and lowercase hex ``proof``.

    Raises:
        ValueError: If the public key is not valid Base64, has an invalid length,
            or inputs are malformed.
    """
    if not isinstance(public_key_b64, str) or not public_key_b64:
        raise ValueError("public_key_b64 must be a non-empty Base64 string")
    if not isinstance(challenge, str) or not isinstance(body, str):
        raise ValueError("challenge and body must be strings")

    try:
        public_key = base64.b64decode(public_key_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("Invalid Base64 public key") from exc

    if len(public_key) != PUBLIC_KEY_SIZE:
        raise ValueError(
            f"Invalid ML-KEM-768 public key length: expected {PUBLIC_KEY_SIZE} bytes, got {len(public_key)}"
        )

    try:
        ciphertext, shared_secret = encrypt(public_key)
    except Exception as exc:
        raise ValueError("Failed to encapsulate shared secret with provided public key") from exc

    message = (challenge + body).encode("utf-8")
    proof = hmac.new(shared_secret, message, hashlib.sha256).hexdigest()

    return {
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "proof": proof,
    }
