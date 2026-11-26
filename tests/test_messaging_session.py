"""Tests for messaging.session."""

from __future__ import annotations

import base64
from copy import deepcopy
import json
from pathlib import Path
from typing import Any

import pytest
from pqcrypto.kem import ml_kem_768
from pqcrypto.sign.ml_dsa_65 import generate_keypair as generate_dsa_keypair

from messaging import session as msg_session


@pytest.fixture(autouse=True)
def isolated_session_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Isolate replay state directory and in-memory registries per test."""
    state_dir = tmp_path / "msg_state"
    monkeypatch.setenv("MSG_STATE_DIR", str(state_dir))
    msg_session.clear_state_for_tests()
    yield state_dir
    msg_session.clear_state_for_tests()


def _setup_users() -> tuple[bytes, bytes]:
    alice_pk, alice_sk = generate_dsa_keypair()
    bob_pk, bob_sk = generate_dsa_keypair()
    msg_session.register_identity("alice", alice_pk)
    msg_session.register_identity("bob", bob_pk)
    return alice_sk, bob_sk


def test_round_trip_and_bidirectional_separation() -> None:
    alice_sk, bob_sk = _setup_users()
    events: list[dict[str, Any]] = []
    sid = msg_session.start_session("alice", "bob", alice_sk, bob_sk, log_event=events.append)

    pkt_ab = msg_session.send(sid, "alice", "bob", b"hello bob", log_event=events.append)
    assert isinstance(pkt_ab, dict)
    assert msg_session.receive(sid, "bob", pkt_ab, log_event=events.append) == b"hello bob"

    pkt_ba = msg_session.send(sid, "bob", "alice", b"hello alice", log_event=events.append)
    assert isinstance(pkt_ba, dict)
    assert msg_session.receive(sid, "alice", pkt_ba, log_event=events.append) == b"hello alice"

    # Separate keys per direction and distinct nonces.
    s_alice = msg_session._ACTIVE_SESSIONS[(sid, "alice")]
    s_bob = msg_session._ACTIVE_SESSIONS[(sid, "bob")]
    assert s_alice.send_key != s_alice.recv_key
    assert s_alice.send_key == s_bob.recv_key
    assert pkt_ab["nonce"] != pkt_ba["nonce"]

    # Audit events carry required fields and never expose keys or plaintext.
    required = {"event_id", "ts", "node", "actor", "action", "target", "result", "details"}
    assert len(events) >= 5
    serialized_events = json.dumps(events)
    assert "hello bob" not in serialized_events
    assert "hello alice" not in serialized_events
    for event in events:
        assert set(event.keys()) == required


def test_chunked_round_trip_uses_unique_nonces() -> None:
    alice_sk, bob_sk = _setup_users()
    sid = msg_session.start_session("alice", "bob", alice_sk, bob_sk)

    payload = b"abcdefghijklmnopqrstuvwxyz"
    packets = msg_session.send(sid, "alice", "bob", payload, chunk_size=10)
    assert isinstance(packets, list)
    assert len(packets) == 3

    nonces = [pkt["nonce"] for pkt in packets]
    assert len(set(nonces)) == 3
    assert [pkt["header"]["chunk_index"] for pkt in packets] == [0, 1, 2]
    assert all(pkt["header"]["chunk_total"] == 3 for pkt in packets)

    assert msg_session.receive(sid, "bob", packets) == payload


def test_eavesdropper_cannot_decrypt(tmp_path: Path) -> None:
    alice_sk, bob_sk = _setup_users()
    eve_pk, eve_sk = generate_dsa_keypair()
    msg_session.register_identity("eve", eve_pk)

    sid = msg_session.start_session("alice", "bob", alice_sk, bob_sk)
    secret_text = b"top-secret-quantum-payload"
    pkt = msg_session.send(sid, "alice", "bob", secret_text)
    assert isinstance(pkt, dict)

    # Raw wire packet does not contain plaintext.
    assert secret_text not in json.dumps(pkt).encode("utf-8")

    # Eve cannot decrypt via her own session or via receive() on Alice/Bob's session.
    eve_sid = msg_session.start_session("alice", "eve", alice_sk, eve_sk)
    with pytest.raises(msg_session.SessionError) as eve_exc:
        msg_session.receive(eve_sid, "eve", pkt)
    assert eve_exc.value.reason_code == msg_session.REASON_UNKNOWN_SESSION

    with pytest.raises(msg_session.SessionError) as intercept_exc:
        msg_session.receive(sid, "eve", pkt)
    assert intercept_exc.value.reason_code == msg_session.REASON_WRONG_RECIPIENT


def test_replay_rejected() -> None:
    alice_sk, bob_sk = _setup_users()
    sid = msg_session.start_session("alice", "bob", alice_sk, bob_sk)

    pkt = msg_session.send(sid, "alice", "bob", b"once only")
    assert isinstance(pkt, dict)
    assert msg_session.receive(sid, "bob", pkt) == b"once only"

    with pytest.raises(msg_session.SessionError) as exc_info:
        msg_session.receive(sid, "bob", pkt)
    assert exc_info.value.reason_code == msg_session.REASON_REPLAY


def test_changed_recipient_rejected() -> None:
    alice_sk, bob_sk = _setup_users()
    sid = msg_session.start_session("alice", "bob", alice_sk, bob_sk)

    pkt = msg_session.send(sid, "alice", "bob", b"for bob")
    assert isinstance(pkt, dict)
    tampered = deepcopy(pkt)
    tampered["header"]["recipient"] = "mallory"

    with pytest.raises(msg_session.SessionError) as exc_info:
        msg_session.receive(sid, "bob", tampered)
    assert exc_info.value.reason_code == msg_session.REASON_WRONG_RECIPIENT


def test_flipped_byte_rejected() -> None:
    alice_sk, bob_sk = _setup_users()
    sid = msg_session.start_session("alice", "bob", alice_sk, bob_sk)

    pkt = msg_session.send(sid, "alice", "bob", b"integrity check")
    assert isinstance(pkt, dict)

    # Flip one bit in the ciphertext.
    tampered_ct = bytearray(base64.b64decode(pkt["ciphertext"]))
    tampered_ct[0] ^= 0x01
    tampered = deepcopy(pkt)
    tampered["ciphertext"] = base64.b64encode(bytes(tampered_ct)).decode("ascii")

    with pytest.raises(msg_session.SessionError) as exc_info:
        msg_session.receive(sid, "bob", tampered)
    assert exc_info.value.reason_code == msg_session.REASON_TAMPERED

    # Flipping header metadata (e.g., counter) also fails authentication.
    tampered_hdr = deepcopy(pkt)
    tampered_hdr["header"]["counter"] = 999
    with pytest.raises(msg_session.SessionError) as hdr_exc:
        msg_session.receive(sid, "bob", tampered_hdr)
    assert hdr_exc.value.reason_code == msg_session.REASON_TAMPERED


def test_unknown_session_rejected() -> None:
    _setup_users()
    fake_pkt = {
        "header": {
            "version": 1,
            "session_id": "nonexistent-session",
            "sender": "alice",
            "recipient": "bob",
            "counter": 1,
            "chunk_index": 0,
            "chunk_total": 1,
        },
        "nonce": base64.b64encode(b"\x00" * 12).decode("ascii"),
        "ciphertext": base64.b64encode(b"bad").decode("ascii"),
    }
    with pytest.raises(msg_session.SessionError) as exc_info:
        msg_session.receive("nonexistent-session", "bob", fake_pkt)
    assert exc_info.value.reason_code == msg_session.REASON_UNKNOWN_SESSION


def test_bad_signature_rejected_before_key_use(monkeypatch: pytest.MonkeyPatch) -> None:
    alice_sk, bob_sk = _setup_users()

    # Corrupt initiator signature and verify KEM encapsulation is never called.
    init_msg, init_state = msg_session.initiate_handshake("alice", "bob", alice_sk)
    bad_init_sig = bytearray(init_msg.signature)
    bad_init_sig[0] ^= 0xFF
    corrupt_init = msg_session.HandshakeInit(
        version=init_msg.version,
        session_id=init_msg.session_id,
        sender=init_msg.sender,
        recipient=init_msg.recipient,
        x25519_pk=init_msg.x25519_pk,
        kem_pk=init_msg.kem_pk,
        signature=bytes(bad_init_sig),
    )

    def _forbid_encrypt(_pk: bytes) -> tuple[bytes, bytes]:
        raise AssertionError("ml_kem_encrypt must not be called before signature verification")

    monkeypatch.setattr(msg_session, "ml_kem_encrypt", _forbid_encrypt)
    with pytest.raises(msg_session.SessionError) as exc_init:
        msg_session.respond_handshake("bob", bob_sk, corrupt_init)
    assert exc_init.value.reason_code == msg_session.REASON_BAD_SIGNATURE
    monkeypatch.undo()

    # Valid init, corrupt responder signature -> verify KEM decrypt is never called.
    resp_msg = msg_session.respond_handshake("bob", bob_sk, init_msg)
    bad_resp_sig = bytearray(resp_msg.signature)
    bad_resp_sig[0] ^= 0xFF
    corrupt_resp = msg_session.HandshakeResponse(
        version=resp_msg.version,
        session_id=resp_msg.session_id,
        sender=resp_msg.sender,
        recipient=resp_msg.recipient,
        kem_ct=resp_msg.kem_ct,
        x25519_pk=resp_msg.x25519_pk,
        signature=bytes(bad_resp_sig),
    )

    def _forbid_decrypt(_sk: bytes, _ct: bytes) -> bytes:
        raise AssertionError("ml_kem_decrypt must not be called before signature verification")

    monkeypatch.setattr(msg_session, "ml_kem_decrypt", _forbid_decrypt)
    with pytest.raises(msg_session.SessionError) as exc_resp:
        msg_session.complete_handshake(init_state, corrupt_resp)
    assert exc_resp.value.reason_code == msg_session.REASON_BAD_SIGNATURE
    msg_session.close_session(init_msg.session_id)


def test_old_session_unreadable_after_identity_key_leaks(tmp_path: Path) -> None:
    alice_sk, bob_sk = _setup_users()

    # Record all handshake and message wire traffic from the old session.
    init_msg, init_state = msg_session.initiate_handshake("alice", "bob", alice_sk)
    resp_msg = msg_session.respond_handshake("bob", bob_sk, init_msg)
    sid = msg_session.complete_handshake(init_state, resp_msg)

    recorded_pkt = msg_session.send(sid, "alice", "bob", b"past-session-confidential-data")
    assert isinstance(recorded_pkt, dict)
    assert msg_session.receive(sid, "bob", recorded_pkt) == b"past-session-confidential-data"

    # Ephemeral private keys were destroyed at handshake completion.
    assert init_state.eph_x25519_sk is None
    assert init_state.eph_kem_sk is None

    # Close session -> deletes symmetric session keys from memory.
    msg_session.close_session(sid)

    # Attacker now steals BOTH long-term ML-DSA-65 identity private keys (alice_sk, bob_sk)
    # and possesses full recorded traffic (init_msg, resp_msg, recorded_pkt).
    leaked_alice_sk = alice_sk
    leaked_bob_sk = bob_sk

    # 1. Closed session cannot be decrypted via API.
    with pytest.raises(msg_session.SessionError) as closed_exc:
        msg_session.receive(sid, "bob", recorded_pkt)
    assert closed_exc.value.reason_code == msg_session.REASON_UNKNOWN_SESSION

    # 2. Even replaying the recorded handshake with leaked identity keys cannot
    #    reproduce the old session's ephemeral X25519 or ML-KEM shared secrets.
    attacker_new_sid = msg_session.start_session(
        "alice", "bob", leaked_alice_sk, leaked_bob_sk
    )
    with pytest.raises(msg_session.SessionError):
        # Attempting to decrypt the old recorded packet under a newly established
        # session (even with leaked identity keys) fails.
        forged_pkt = deepcopy(recorded_pkt)
        forged_pkt["header"]["session_id"] = attacker_new_sid
        msg_session.receive(attacker_new_sid, "bob", forged_pkt)

    # 3. Attempting offline decryption directly from recorded traffic + leaked
    #    identity keys fails: ML-DSA-65 keys are the wrong size/type for ML-KEM,
    #    and even slicing bytes to feed ML-KEM/X25519 + HKDF fails AES-GCM auth.
    with pytest.raises(ValueError):
        ml_kem_768.decrypt(leaked_alice_sk, resp_msg.kem_ct)

    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    bogus_kem_ss = ml_kem_768.decrypt(
        leaked_alice_sk[: ml_kem_768.SECRET_KEY_SIZE], resp_msg.kem_ct
    )
    bogus_x25519_ss = x25519.X25519PrivateKey.from_private_bytes(
        leaked_alice_sk[:32]
    ).exchange(x25519.X25519PublicKey.from_public_bytes(resp_msg.x25519_pk))
    transcript = (
        init_state.init_body
        + init_state.init_sig
        + msg_session._encode_resp_body(
            resp_msg.version,
            resp_msg.session_id,
            resp_msg.sender,
            resp_msg.recipient,
            resp_msg.kem_ct,
            resp_msg.x25519_pk,
        )
    )
    bogus_key = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=None,
        info=transcript,
    ).derive(bogus_x25519_ss + bogus_kem_ss)[:32]
    nonce = base64.b64decode(recorded_pkt["nonce"])
    ciphertext = base64.b64decode(recorded_pkt["ciphertext"])
    aad = msg_session._encode_header_aad(recorded_pkt["header"])
    with pytest.raises(InvalidTag):
        AESGCM(bogus_key).decrypt(nonce, ciphertext, aad)


def test_revocation_and_persisted_state_contains_no_keys(isolated_session_env: Path) -> None:
    alice_sk, bob_sk = _setup_users()
    sid = msg_session.start_session("alice", "bob", alice_sk, bob_sk)
    pkt = msg_session.send(sid, "alice", "bob", b"msg1")
    assert isinstance(pkt, dict)
    assert msg_session.receive(sid, "bob", pkt) == b"msg1"

    state_file = isolated_session_env / "messaging_replay_state.json"
    assert state_file.exists()
    persisted = json.loads(state_file.read_text(encoding="utf-8"))
    assert set(persisted.keys()) == {"sessions"}
    assert sid in persisted["sessions"]
    assert set(persisted["sessions"][sid].keys()) == {"seen_counters"}

    # Revoke sender -> subsequent send and receive reject.
    msg_session.revoke_user("alice")
    with pytest.raises(msg_session.SessionError) as send_exc:
        msg_session.send(sid, "alice", "bob", b"msg2")
    assert send_exc.value.reason_code == msg_session.REASON_REVOKED

    with pytest.raises(msg_session.SessionError) as start_exc:
        msg_session.start_session("alice", "bob", alice_sk, bob_sk)
    assert start_exc.value.reason_code == msg_session.REASON_REVOKED
