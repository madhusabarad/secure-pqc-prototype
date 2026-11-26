"""Tests for messaging.protected_read."""

from __future__ import annotations

import base64
import hashlib
import hmac
import re

import pytest
from pqcrypto.kem.ml_kem_768 import PUBLIC_KEY_SIZE, decrypt, generate_keypair

from messaging.protected_read import protected_read


def test_protected_read_round_trip() -> None:
    pk, sk = generate_keypair()
    pk_b64 = base64.b64encode(pk).decode("ascii")
    challenge = "nonce-12345"
    body = '{"action":"read","id":42}'

    result = protected_read(pk_b64, challenge, body)

    assert result is not None
    assert set(result.keys()) == {"ciphertext", "proof"}

    ciphertext = base64.b64decode(result["ciphertext"], validate=True)
    shared_secret = decrypt(sk, ciphertext)
    expected_proof = hmac.new(
        shared_secret,
        (challenge + body).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    assert result["proof"] == expected_proof


def test_protected_read_proof_is_lowercase_hex_64() -> None:
    pk, _ = generate_keypair()
    pk_b64 = base64.b64encode(pk).decode("ascii")

    result = protected_read(pk_b64, "challenge", "body")

    assert result is not None
    assert isinstance(result["proof"], str)
    assert re.fullmatch(r"[0-9a-f]{64}", result["proof"]) is not None


def test_protected_read_non_ascii_utf8() -> None:
    pk, sk = generate_keypair()
    pk_b64 = base64.b64encode(pk).decode("ascii")
    challenge = "ñ"
    body = "日本"

    result = protected_read(pk_b64, challenge, body)

    assert result is not None
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
        base64.urlsafe_b64encode(b"\xfb" * PUBLIC_KEY_SIZE).decode("ascii"),
        f" {base64.b64encode(b'x' * PUBLIC_KEY_SIZE).decode('ascii')}",
        None,
        12345,
        b"x" * PUBLIC_KEY_SIZE,
    ],
)
def test_protected_read_invalid_key_returns_none(bad_key: object) -> None:
    assert protected_read(bad_key, "challenge", "body") is None  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("bad_challenge", "bad_body"),
    [
        (None, "body"),
        ("challenge", None),
        (123, "body"),
        ("challenge", 456),
        (b"challenge", "body"),
        ("challenge", b"body"),
        ("\ud800", "body"),
    ],
)
def test_protected_read_invalid_message_inputs_return_none(
    bad_challenge: object, bad_body: object
) -> None:
    pk, _ = generate_keypair()
    pk_b64 = base64.b64encode(pk).decode("ascii")

    assert protected_read(pk_b64, bad_challenge, bad_body) is None  # type: ignore[arg-type]
