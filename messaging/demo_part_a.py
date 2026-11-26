"""Self-contained demonstration of Part A secure messaging guarantees."""

from __future__ import annotations

from copy import deepcopy
import base64
import os
import sys
import tempfile

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pqcrypto.kem import ml_kem_768
from pqcrypto.sign.ml_dsa_65 import generate_keypair as generate_dsa_keypair

from messaging import session as msg_session


def _check(condition: bool, label: str) -> None:
    """Print failure label and exit non-zero if condition is false."""
    if not condition:
        print(f"FAIL: {label}")
        sys.exit(1)


def run_demo() -> None:
    """Run all Part A messaging scenarios in an isolated temporary state directory."""
    prev_state_dir = os.environ.get("MSG_STATE_DIR")
    msg_session.clear_state_for_tests()

    with tempfile.TemporaryDirectory(prefix="pqc_msg_demo_") as tmp_dir:
        os.environ["MSG_STATE_DIR"] = tmp_dir
        try:
            alice_pk, alice_sk = generate_dsa_keypair()
            bob_pk, bob_sk = generate_dsa_keypair()
            msg_session.register_identity("alice", alice_pk)
            msg_session.register_identity("bob", bob_pk)

            # 1. Handshake + round trip Alice -> Bob
            sid = msg_session.start_session("alice", "bob", alice_sk, bob_sk)
            pkt_roundtrip = msg_session.send(sid, "alice", "bob", b"Hello Bob from Alice")
            _check(isinstance(pkt_roundtrip, dict), "roundtrip packet is dict")
            res_roundtrip = msg_session.receive(sid, "bob", pkt_roundtrip)
            _check(res_roundtrip.status == msg_session.STATUS_DELIVERED, "roundtrip delivered")
            _check(res_roundtrip.plaintext == b"Hello Bob from Alice", "roundtrip plaintext matches")
            print(
                f"1. Handshake + round trip Alice->Bob: {res_roundtrip.status} "
                f"({len(res_roundtrip.plaintext)} bytes)"
            )

            # 2. Replayed message -> REPLAY
            res_replay = msg_session.receive(sid, "bob", pkt_roundtrip)
            _check(res_replay.status == msg_session.STATUS_FAILED, "replay status failed")
            _check(res_replay.reason_code == msg_session.REASON_REPLAY, "replay reason code")
            print(f"2. Replayed message: {res_replay.status} -> {res_replay.reason_code}")

            # 3. Changed recipient -> WRONG_RECIPIENT
            pkt_recipient = msg_session.send(sid, "alice", "bob", b"Recipient check")
            _check(isinstance(pkt_recipient, dict), "recipient packet is dict")
            bad_recipient_pkt = deepcopy(pkt_recipient)
            bad_recipient_pkt["header"]["recipient"] = "mallory"
            res_wrong_recipient = msg_session.receive(sid, "bob", bad_recipient_pkt)
            _check(res_wrong_recipient.status == msg_session.STATUS_FAILED, "wrong recipient status failed")
            _check(res_wrong_recipient.reason_code == msg_session.REASON_WRONG_RECIPIENT, "wrong recipient reason code")
            print(
                f"3. Changed recipient: {res_wrong_recipient.status} -> "
                f"{res_wrong_recipient.reason_code}"
            )

            # 4. Flipped byte -> TAMPERED
            pkt_tamper = msg_session.send(sid, "alice", "bob", b"Integrity check")
            _check(isinstance(pkt_tamper, dict), "tamper packet is dict")
            tampered_pkt = deepcopy(pkt_tamper)
            raw_ct = bytearray(base64.b64decode(tampered_pkt["ciphertext"]))
            raw_ct[0] ^= 0x01
            tampered_pkt["ciphertext"] = base64.b64encode(bytes(raw_ct)).decode("ascii")
            res_tampered = msg_session.receive(sid, "bob", tampered_pkt)
            _check(res_tampered.status == msg_session.STATUS_FAILED, "tampered status failed")
            _check(res_tampered.reason_code == msg_session.REASON_TAMPERED, "tampered reason code")
            print(f"4. Flipped byte: {res_tampered.status} -> {res_tampered.reason_code}")

            # 5. Shuffled chunks delivered
            chunked_payload = b"chunk-0|chunk-1|chunk-2|chunk-3|chunk-4"
            chunk_packets = msg_session.send(
                sid, "alice", "bob", chunked_payload, chunk_size=8
            )
            _check(isinstance(chunk_packets, list), "chunk packets is list")
            _check(len(chunk_packets) == 5, "chunk packets count == 5")
            shuffled = [
                chunk_packets[3],
                chunk_packets[0],
                chunk_packets[4],
                chunk_packets[1],
                chunk_packets[2],
            ]
            for pkt in shuffled[:-1]:
                pending_res = msg_session.receive(sid, "bob", pkt, now=100.0)
                _check(pending_res.status == msg_session.STATUS_PENDING, "shuffled chunk pending")
            res_shuffled = msg_session.receive(sid, "bob", shuffled[-1], now=101.0)
            _check(res_shuffled.status == msg_session.STATUS_DELIVERED, "shuffled chunks delivered")
            _check(res_shuffled.plaintext == chunked_payload, "shuffled plaintext matches")
            print(
                f"5. Shuffled chunks ({len(shuffled)} chunks): {res_shuffled.status} "
                f"({len(res_shuffled.plaintext)} bytes)"
            )

            # 6. Dropped chunk -> FAILED after expire_incomplete (fake clock, no sleep)
            drop_packets = msg_session.send(
                sid, "alice", "bob", b"incomplete-chunked-msg", chunk_size=8
            )
            _check(isinstance(drop_packets, list), "drop packets is list")
            _check(len(drop_packets) == 3, "drop packets count == 3")
            _check(msg_session.receive(sid, "bob", drop_packets[0], now=1000.0).status == msg_session.STATUS_PENDING, "first drop chunk pending")
            _check(msg_session.receive(sid, "bob", drop_packets[2], now=1010.0).status == msg_session.STATUS_PENDING, "third drop chunk pending")
            expired = msg_session.expire_incomplete(now=1030.0, session_id=sid, recipient="bob")
            _check(len(expired) == 1, "expired count == 1")
            _check(expired[0].status == msg_session.STATUS_FAILED, "expired status failed")
            _check(expired[0].reason_code == msg_session.REASON_INCOMPLETE_TIMEOUT, "expired reason code")
            print(
                f"6. Dropped chunk after expire_incomplete: {expired[0].status} -> "
                f"{expired[0].reason_code}"
            )

            msg_session.close_session(sid)

            # 7. Old session unreadable after identity key leak
            init_msg, init_state = msg_session.initiate_handshake("alice", "bob", alice_sk)
            resp_msg = msg_session.respond_handshake("bob", bob_sk, init_msg)
            old_sid = msg_session.complete_handshake(init_state, resp_msg)
            recorded_pkt = msg_session.send(old_sid, "alice", "bob", b"past-session-record")
            _check(isinstance(recorded_pkt, dict), "recorded packet is dict")
            msg_session.close_session(old_sid)

            # Attacker obtains both long-term ML-DSA-65 signing keys after close_session()
            closed_res = msg_session.receive(old_sid, "bob", recorded_pkt)
            _check(closed_res.status == msg_session.STATUS_FAILED, "closed session status failed")
            _check(closed_res.reason_code == msg_session.REASON_UNKNOWN_SESSION, "closed session reason code")

            new_sid = msg_session.start_session("alice", "bob", alice_sk, bob_sk)
            forged_pkt = deepcopy(recorded_pkt)
            forged_pkt["header"]["session_id"] = new_sid
            new_sid_res = msg_session.receive(new_sid, "bob", forged_pkt)
            _check(new_sid_res.status == msg_session.STATUS_FAILED, "forged new_sid status failed")

            bogus_kem_ss = ml_kem_768.decrypt(
                alice_sk[: ml_kem_768.SECRET_KEY_SIZE], resp_msg.kem_ct
            )
            bogus_x25519_ss = x25519.X25519PrivateKey.from_private_bytes(
                alice_sk[:32]
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
            offline_failed = False
            try:
                AESGCM(bogus_key).decrypt(
                    base64.b64decode(recorded_pkt["nonce"]),
                    base64.b64decode(recorded_pkt["ciphertext"]),
                    msg_session._encode_header_aad(recorded_pkt["header"]),
                )
            except InvalidTag:
                offline_failed = True
            _check(offline_failed, "offline decryption failed")
            print(
                "7. Old session after identity key leak: UNREADABLE "
                f"({closed_res.reason_code}, offline InvalidTag)"
            )
        finally:
            msg_session.clear_state_for_tests()
            if prev_state_dir is None:
                os.environ.pop("MSG_STATE_DIR", None)
            else:
                os.environ["MSG_STATE_DIR"] = prev_state_dir


if __name__ == "__main__":
    run_demo()
