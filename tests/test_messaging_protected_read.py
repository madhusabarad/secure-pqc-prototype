"""Tests for messaging.protected_read."""

from __future__ import annotations

import base64
import hashlib
import hmac

import pytest
from pqcrypto.kem.ml_kem_768 import PUBLIC_KEY_SIZE, decrypt, generate_keypair

from messaging.protected_read import protected_read


def test_protected_read_round_trip() -> None:
    pk, sk = generate_keypair()
    pk_b64 = base64.b64encode(pk).decode("ascii")
    challenge = "nonce-12345"
    body = '{"action":"read","id":42}'

    result = protected_read(pk_b64, challenge, body)

    assert set(result.keys()) == {"ciphertext", "proof"}
    assert len(result["proof"]) == 64
    assert result["proof"] == result["proof"].lower()

    ciphertext = base64.b64decode(result["ciphertext"], validate=True)
    shared_secret = decrypt(sk, ciphertext)
    expected_proof = hmac.new(
        shared_secret,
        (challenge + body).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    assert result["proof"] == expected_proof


@pytest.mark.parametrize(
    "bad_key",
    [
        "",
        "!!!not-base64!!!",
        "YWJj",  # valid base64, too short
        base64.b64encode(b"x" * (PUBLIC_KEY_SIZE - 1)).decode("ascii"),
        base64.b64encode(b"x" * (PUBLIC_KEY_SIZE + 1)).decode("ascii"),
        None,
        12345,
    ],
)
def test_protected_read_invalid_key_raises_value_error(bad_key: object) -> None:
    with pytest.raises(ValueError):
        protected_read(bad_key, "challenge", "body")  # type: ignore[arg-type]


def test_protected_read_invalid_message_inputs_raise_value_error() -> None:
    pk, _ = generate_keypair()
    pk_b64 = base64.b64encode(pk).decode("ascii")

    with pytest.raises(ValueError):
        protected_read(pk_b64, None, "body")  # type: ignore[arg-type]

    with pytest.raises(ValueError):
        protected_read(pk_b64, "challenge", None)  # type: ignore[arg-type]
