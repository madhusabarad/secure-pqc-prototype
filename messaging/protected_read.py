"""Protected read KEM encapsulation and HMAC proof helper."""

import base64
import hashlib
import hmac

from pqcrypto.kem.ml_kem_768 import encrypt

_ML_KEM_768_PUBLIC_KEY_SIZE = 1184


def protected_read(public_key_b64: str, challenge: str, body: str) -> dict[str, str] | None:
    """Encapsulate a shared secret to an ML-KEM-768 public key and sign challenge+body via HMAC-SHA256.

    Args:
        public_key_b64: Standard Base64-encoded 1184-byte ML-KEM-768 public key.
        challenge: Challenge string.
        body: Body string.

    Returns:
        Dictionary containing standard Base64-encoded ``ciphertext`` and
        lowercase hex ``proof``, or ``None`` if any input or operation fails.
    """
    try:
        if (
            not isinstance(public_key_b64, str)
            or not isinstance(challenge, str)
            or not isinstance(body, str)
        ):
            return None

        public_key = base64.b64decode(public_key_b64, validate=True)
        if len(public_key) != _ML_KEM_768_PUBLIC_KEY_SIZE:
            return None

        ciphertext, shared_secret = encrypt(public_key)
        message = (challenge + body).encode("utf-8")
        proof = hmac.new(shared_secret, message, hashlib.sha256).hexdigest()

        return {
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            "proof": proof,
        }
    except Exception:
        return None
