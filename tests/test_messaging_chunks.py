"""Tests for receiver chunk reassembly, ordering, expiration, and limits."""

from __future__ import annotations

import base64
from copy import deepcopy
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import pytest
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


def _start_alice_bob_session() -> str:
    alice_pk, alice_sk = generate_dsa_keypair()
    bob_pk, bob_sk = generate_dsa_keypair()
    msg_session.register_identity("alice", alice_pk)
    msg_session.register_identity("bob", bob_pk)
    return msg_session.start_session("alice", "bob", alice_sk, bob_sk)


def _craft_authenticated_chunk(
    session_id: str,
    sender: str,
    recipient: str,
    *,
    msg_id: str,
    chunk_index: int,
    chunk_total: int,
    payload: bytes,
) -> dict[str, Any]:
    """Build a validly encrypted chunk using the sender's active session key."""
    sender_session = msg_session._ACTIVE_SESSIONS[(session_id, sender)]
    assert sender_session.send_key is not None
    sender_session.send_counter += 1
    counter = sender_session.send_counter
    header = {
        "version": msg_session.PROTOCOL_VERSION,
        "session_id": session_id,
        "msg_id": msg_id,
        "sender": sender,
        "recipient": recipient,
        "counter": counter,
        "chunk_index": chunk_index,
        "chunk_total": chunk_total,
    }
    aad = msg_session._encode_header_aad(header)
    nonce = msg_session._derive_nonce(sender_session.send_direction, counter)
    ciphertext = AESGCM(bytes(sender_session.send_key)).encrypt(nonce, payload, aad)
    return {
        "header": header,
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }


def test_shuffled_chunks_delivered_correctly() -> None:
    sid = _start_alice_bob_session()
    events: list[dict[str, Any]] = []
    payload = b"0123456789abcdefghijKLMNOPQRSTuvwxyz"
    packets = msg_session.send(sid, "alice", "bob", payload, chunk_size=8)
    assert isinstance(packets, list)
    assert len(packets) == 5

    shuffled = [packets[3], packets[0], packets[4], packets[1], packets[2]]
    for pkt in shuffled[:-1]:
        res = msg_session.receive(sid, "bob", pkt, now=100.0, log_event=events.append)
        assert res.status == msg_session.STATUS_PENDING
        assert res.reason_code is None
        assert res.plaintext is None

    final_res = msg_session.receive(sid, "bob", shuffled[-1], now=101.0, log_event=events.append)
    assert final_res.status == msg_session.STATUS_DELIVERED
    assert final_res.reason_code is None
    assert final_res.plaintext == payload
    assert msg_session._ACTIVE_SESSIONS[(sid, "bob")].chunk_buffers == {}

    # Only DELIVERED logged (never plaintext or keys).
    assert len(events) == 1
    assert events[0]["result"] == msg_session.STATUS_DELIVERED
    assert payload.decode("ascii") not in json.dumps(events)


def test_one_dropped_chunk_fails_after_expire_incomplete() -> None:
    sid = _start_alice_bob_session()
    events: list[dict[str, Any]] = []
    packets = msg_session.send(sid, "alice", "bob", b"secret-chunked-data", chunk_size=7)
    assert isinstance(packets, list)
    assert len(packets) == 3
    msg_id = packets[0]["header"]["msg_id"]

    # Deliver chunk 0 and chunk 2; drop chunk 1.
    r0 = msg_session.receive(sid, "bob", packets[0], now=1000.0, log_event=events.append)
    r2 = msg_session.receive(sid, "bob", packets[2], now=1010.0, log_event=events.append)
    assert r0.status == msg_session.STATUS_PENDING and r0.plaintext is None
    assert r2.status == msg_session.STATUS_PENDING and r2.plaintext is None

    # Before 30s timeout: nothing expires.
    assert msg_session.expire_incomplete(1029.5, log_event=events.append) == []
    assert len(msg_session._ACTIVE_SESSIONS[(sid, "bob")].chunk_buffers) == 1

    # At 30s timeout: discarded and reported as FAILED / INCOMPLETE_TIMEOUT.
    expired = msg_session.expire_incomplete(1030.0, log_event=events.append)
    assert len(expired) == 1
    assert expired[0].status == msg_session.STATUS_FAILED
    assert expired[0].reason_code == msg_session.REASON_INCOMPLETE_TIMEOUT
    assert expired[0].plaintext is None
    assert expired[0].session_id == sid
    assert expired[0].msg_id == msg_id
    assert msg_session._ACTIVE_SESSIONS[(sid, "bob")].chunk_buffers == {}

    # Late arrival of dropped chunk is rejected as FAILED and never delivers partial data.
    late_res = msg_session.receive(sid, "bob", packets[1], now=1031.0, log_event=events.append)
    assert late_res.status == msg_session.STATUS_FAILED
    assert late_res.reason_code == msg_session.REASON_INCOMPLETE_TIMEOUT
    assert late_res.plaintext is None

    assert any(
        ev["result"] == msg_session.STATUS_FAILED
        and ev["details"].get("reason_code") == msg_session.REASON_INCOMPLETE_TIMEOUT
        for ev in events
    )
    assert "secret" not in json.dumps(events)


def test_duplicate_chunk_ignored_and_message_completes() -> None:
    sid = _start_alice_bob_session()
    payload = b"alpha-beta-gamma"
    packets = msg_session.send(sid, "alice", "bob", payload, chunk_size=6)
    assert isinstance(packets, list)
    assert len(packets) == 3

    r0 = msg_session.receive(sid, "bob", packets[0], now=10.0)
    assert r0.status == msg_session.STATUS_PENDING
    assert r0.reason_code is None

    dup = msg_session.receive(sid, "bob", packets[0], now=11.0)
    assert dup.status == msg_session.STATUS_PENDING
    assert dup.reason_code == msg_session.REASON_DUPLICATE_CHUNK
    assert dup.plaintext is None

    r2 = msg_session.receive(sid, "bob", packets[2], now=12.0)
    assert r2.status == msg_session.STATUS_PENDING
    assert r2.plaintext is None

    r1 = msg_session.receive(sid, "bob", packets[1], now=13.0)
    assert r1.status == msg_session.STATUS_DELIVERED
    assert r1.plaintext == payload


def test_tampered_chunk_rejected_and_message_not_delivered() -> None:
    sid = _start_alice_bob_session()
    events: list[dict[str, Any]] = []
    payload = b"chunk0-chunk1-chunk2"
    packets = msg_session.send(sid, "alice", "bob", payload, chunk_size=7)
    assert isinstance(packets, list)
    assert len(packets) == 3

    r0 = msg_session.receive(sid, "bob", packets[0], now=50.0, log_event=events.append)
    assert r0.status == msg_session.STATUS_PENDING

    # Tamper ciphertext of chunk 1 -> rejected immediately, never buffered.
    tampered_pkt = deepcopy(packets[1])
    raw_ct = bytearray(base64.b64decode(tampered_pkt["ciphertext"]))
    raw_ct[0] ^= 0x40
    tampered_pkt["ciphertext"] = base64.b64encode(bytes(raw_ct)).decode("ascii")

    tampered_res = msg_session.receive(sid, "bob", tampered_pkt, now=51.0, log_event=events.append)
    assert tampered_res.status == msg_session.STATUS_FAILED
    assert tampered_res.reason_code == msg_session.REASON_TAMPERED
    assert tampered_res.plaintext is None

    # Tamper header AAD (chunk_index) on chunk 1 -> also rejected.
    tampered_hdr = deepcopy(packets[1])
    tampered_hdr["header"]["chunk_index"] = 2
    hdr_res = msg_session.receive(sid, "bob", tampered_hdr, now=51.5, log_event=events.append)
    assert hdr_res.status == msg_session.STATUS_FAILED
    assert hdr_res.reason_code == msg_session.REASON_TAMPERED
    assert hdr_res.plaintext is None

    # Chunk 2 arrives, but tampered chunk 1 was never buffered -> message still not delivered.
    r2 = msg_session.receive(sid, "bob", packets[2], now=52.0, log_event=events.append)
    assert r2.status == msg_session.STATUS_PENDING
    assert r2.plaintext is None

    # Only 2 valid chunks (0 and 2) were ever buffered.
    buf = next(iter(msg_session._ACTIVE_SESSIONS[(sid, "bob")].chunk_buffers.values()))
    assert set(buf.chunks.keys()) == {0, 2}

    assert any(
        ev["result"] == msg_session.STATUS_FAILED
        and ev["details"].get("reason_code") == msg_session.REASON_TAMPERED
        for ev in events
    )
    assert "chunk0" not in json.dumps(events)


def test_inconsistent_chunk_total_fails_whole_message() -> None:
    sid = _start_alice_bob_session()
    msg_id = "msg-conflict-total"
    c0 = _craft_authenticated_chunk(
        sid, "alice", "bob", msg_id=msg_id, chunk_index=0, chunk_total=3, payload=b"part0"
    )
    c1_bad_total = _craft_authenticated_chunk(
        sid, "alice", "bob", msg_id=msg_id, chunk_index=1, chunk_total=4, payload=b"part1"
    )
    c2 = _craft_authenticated_chunk(
        sid, "alice", "bob", msg_id=msg_id, chunk_index=2, chunk_total=3, payload=b"part2"
    )

    r0 = msg_session.receive(sid, "bob", c0, now=10.0)
    assert r0.status == msg_session.STATUS_PENDING

    r1 = msg_session.receive(sid, "bob", c1_bad_total, now=11.0)
    assert r1.status == msg_session.STATUS_FAILED
    assert r1.reason_code == msg_session.REASON_INCONSISTENT_CHUNKS
    assert r1.plaintext is None
    # Whole message buffer discarded.
    assert msg_session._ACTIVE_SESSIONS[(sid, "bob")].chunk_buffers == {}

    # Subsequent chunk for the failed message also fails and is never buffered.
    r2 = msg_session.receive(sid, "bob", c2, now=12.0)
    assert r2.status == msg_session.STATUS_FAILED
    assert r2.reason_code == msg_session.REASON_INCONSISTENT_CHUNKS
    assert r2.plaintext is None
    assert msg_session._ACTIVE_SESSIONS[(sid, "bob")].chunk_buffers == {}


def test_buffer_limits_enforced() -> None:
    sid = _start_alice_bob_session()

    # 1. Max chunks per message (default 64): 65 chunks -> TOO_LARGE, never buffered.
    oversized_packets = msg_session.send(sid, "alice", "bob", b"x" * 65, chunk_size=1)
    assert isinstance(oversized_packets, list)
    assert len(oversized_packets) == 65
    res_large = msg_session.receive(sid, "bob", oversized_packets[0], now=200.0)
    assert res_large.status == msg_session.STATUS_FAILED
    assert res_large.reason_code == msg_session.REASON_TOO_LARGE
    assert res_large.plaintext is None
    assert msg_session._ACTIVE_SESSIONS[(sid, "bob")].chunk_buffers == {}

    # 2. Max pending messages (default 32): buffer 32 incomplete messages, 33rd -> BUFFER_FULL.
    pending_second_chunks: list[dict[str, Any]] = []
    for idx in range(msg_session.DEFAULT_MAX_PENDING_MESSAGES):
        pkts = msg_session.send(sid, "alice", "bob", f"msg-{idx:02d}-body".encode("utf-8"), chunk_size=7)
        assert isinstance(pkts, list)
        res = msg_session.receive(sid, "bob", pkts[0], now=200.0)
        assert res.status == msg_session.STATUS_PENDING
        pending_second_chunks.append(pkts[1])

    assert len(msg_session._ACTIVE_SESSIONS[(sid, "bob")].chunk_buffers) == 32

    overflow_pkts = msg_session.send(sid, "alice", "bob", b"overflow-message", chunk_size=8)
    assert isinstance(overflow_pkts, list)
    res_full = msg_session.receive(sid, "bob", overflow_pkts[0], now=201.0)
    assert res_full.status == msg_session.STATUS_FAILED
    assert res_full.reason_code == msg_session.REASON_BUFFER_FULL
    assert res_full.plaintext is None
    assert len(msg_session._ACTIVE_SESSIONS[(sid, "bob")].chunk_buffers) == 32

    # Completing an already-buffered message frees a slot, allowing the 33rd to buffer.
    done_res = msg_session.receive(sid, "bob", pending_second_chunks[0], now=202.0)
    assert done_res.status == msg_session.STATUS_DELIVERED
    assert done_res.plaintext == b"msg-00-body"

    retry_res = msg_session.receive(sid, "bob", overflow_pkts[0], now=203.0)
    assert retry_res.status == msg_session.STATUS_PENDING
    assert len(msg_session._ACTIVE_SESSIONS[(sid, "bob")].chunk_buffers) == 32
