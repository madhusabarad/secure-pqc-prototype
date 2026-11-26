"""Authenticated post-quantum + X25519 hybrid messaging session module.

This module implements an authenticated hybrid key exchange (ML-DSA-65 signatures
over ephemeral X25519 + ML-KEM-768 keys) and directional AES-256-GCM message
transport with replay protection.

Forward Secrecy Guarantees and Limitations:
    What forward secrecy DOES cover:
        - Compromise of either party's long-term ML-DSA-65 identity signing
          private keys *after* a handshake completes cannot decrypt past or
          recorded session traffic. Session keys are derived from fresh
          ephemeral X25519 and ephemeral ML-KEM-768 secrets via HKDF-SHA256
          bound to the full handshake transcript, and ephemeral private keys
          are deleted immediately after key derivation.
        - Calling ``close_session()`` deletes all in-memory symmetric session
          keys and any remaining ephemeral private keys for that session. Session
          keys are never written to disk.

    What forward secrecy DOES NOT cover:
        - Compromise of an active session's in-memory symmetric keys (or process
          memory inspection) *before* ``close_session()`` is called allows
          decrypting messages within that active session, because keys do not
          ratchet per message within a session.
        - Compromise of long-term ML-DSA-65 identity signing keys *before* or
          *during* a handshake allows an active person-in-the-middle attacker to
          impersonate the compromised identity in new or in-flight handshakes.
        - Physical/OS memory retention (e.g., Python immutable ``bytes`` copies,
          swap, or core dumps) beyond best-effort ``bytearray`` zeroing and
          reference deletion.
        - Endpoint compromise after plaintext has already been decrypted and
          delivered to the application.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import secrets
import struct
import tempfile
from typing import Any, Callable
import uuid

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pqcrypto.kem.ml_kem_768 import (
    CIPHERTEXT_SIZE as ML_KEM_CIPHERTEXT_SIZE,
    PUBLIC_KEY_SIZE as ML_KEM_PUBLIC_KEY_SIZE,
    decrypt as ml_kem_decrypt,
    encrypt as ml_kem_encrypt,
    generate_keypair as ml_kem_generate_keypair,
)
from pqcrypto.sign.ml_dsa_65 import (
    PUBLIC_KEY_SIZE as ML_DSA_PUBLIC_KEY_SIZE,
    sign as ml_dsa_sign,
    verify as ml_dsa_verify,
)

PROTOCOL_VERSION = 1
DEFAULT_CHUNK_SIZE = 65536
_X25519_KEY_SIZE = 32
_AES_256_KEY_SIZE = 32
_DIR_INIT_TO_RESP = 0
_DIR_RESP_TO_INIT = 1
_INIT_TAG = b"PQC-MSG-V1-INIT"
_RESP_TAG = b"PQC-MSG-V1-RESP"
_REPO_ROOT = Path(__file__).resolve().parent.parent
_STATE_FILENAME = "messaging_replay_state.json"

REASON_REPLAY = "REPLAY"
REASON_WRONG_RECIPIENT = "WRONG_RECIPIENT"
REASON_TAMPERED = "TAMPERED"
REASON_UNKNOWN_SESSION = "UNKNOWN_SESSION"
REASON_BAD_SIGNATURE = "BAD_SIGNATURE"
REASON_REVOKED = "REVOKED"

LogEventCallback = Callable[[dict[str, Any]], None]
PublicKeyLookup = Callable[[str], bytes | dict[str, bytes]]
RevocationLookup = Callable[[str], bool]


class SessionError(ValueError):
    """Error raised when session establishment, sending, or receiving fails."""

    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(f"{reason_code}: {message}")
        self.reason_code = reason_code


@dataclass
class HandshakeInit:
    """Initial authenticated handshake message sent by the initiator."""

    version: int
    session_id: str
    sender: str
    recipient: str
    x25519_pk: bytes
    kem_pk: bytes
    signature: bytes


@dataclass
class HandshakeResponse:
    """Authenticated handshake response sent by the responder."""

    version: int
    session_id: str
    sender: str
    recipient: str
    kem_ct: bytes
    x25519_pk: bytes
    signature: bytes


@dataclass
class InitiatorHandshakeState:
    """In-memory ephemeral handshake state held by the initiator until completion."""

    session_id: str
    sender: str
    recipient: str
    eph_x25519_sk: x25519.X25519PrivateKey | None
    eph_kem_sk: bytearray | None
    init_body: bytes
    init_sig: bytes

    def clear_ephemeral_keys(self) -> None:
        """Delete ephemeral private key material from memory."""
        self.eph_x25519_sk = None
        if self.eph_kem_sk is not None:
            _wipe_bytearray(self.eph_kem_sk)
            self.eph_kem_sk = None


@dataclass
class _EndpointSession:
    """In-memory directional symmetric session state for one participant."""

    session_id: str
    owner: str
    peer: str
    send_direction: int
    recv_direction: int
    send_key: bytearray | None
    recv_key: bytearray | None
    send_counter: int = 0
    chunk_buffers: dict[tuple[str, int, int], dict[int, bytes]] = field(default_factory=dict)

    def close(self) -> None:
        """Zero and delete symmetric session keys from memory."""
        if self.send_key is not None:
            _wipe_bytearray(self.send_key)
            self.send_key = None
        if self.recv_key is not None:
            _wipe_bytearray(self.recv_key)
            self.recv_key = None
        self.chunk_buffers.clear()


_PUBLIC_KEY_REGISTRY: dict[str, bytes] = {}
_REVOKED_USERS: set[str] = set()
_ACTIVE_SESSIONS: dict[tuple[str, str], _EndpointSession] = {}
_PENDING_HANDSHAKES: dict[tuple[str, str], InitiatorHandshakeState] = {}


def _wipe_bytearray(buf: bytearray) -> None:
    """Overwrite a mutable byte buffer with zeros."""
    for idx in range(len(buf)):
        buf[idx] = 0


def _pack_fields(*fields: bytes) -> bytes:
    """Encode a sequence of byte strings with 4-byte big-endian length prefixes."""
    parts = [struct.pack(">I", len(item)) + item for item in fields]
    return b"".join(parts)


def _encode_init_body(
    version: int,
    session_id: str,
    sender: str,
    recipient: str,
    x25519_pk: bytes,
    kem_pk: bytes,
) -> bytes:
    return _pack_fields(
        _INIT_TAG,
        struct.pack(">I", version),
        session_id.encode("utf-8"),
        sender.encode("utf-8"),
        recipient.encode("utf-8"),
        x25519_pk,
        kem_pk,
    )


def _encode_resp_body(
    version: int,
    session_id: str,
    sender: str,
    recipient: str,
    kem_ct: bytes,
    x25519_pk: bytes,
) -> bytes:
    return _pack_fields(
        _RESP_TAG,
        struct.pack(">I", version),
        session_id.encode("utf-8"),
        sender.encode("utf-8"),
        recipient.encode("utf-8"),
        kem_ct,
        x25519_pk,
    )


def _derive_directional_keys(
    x25519_ss: bytes,
    kem_ss: bytes,
    transcript: bytes,
) -> tuple[bytearray, bytearray]:
    """Derive distinct 256-bit keys for initiator->responder and responder->initiator."""
    okm = HKDF(
        algorithm=hashes.SHA256(),
        length=_AES_256_KEY_SIZE * 2,
        salt=None,
        info=transcript,
    ).derive(x25519_ss + kem_ss)
    return (
        bytearray(okm[:_AES_256_KEY_SIZE]),
        bytearray(okm[_AES_256_KEY_SIZE:]),
    )


def _derive_nonce(direction: int, counter: int) -> bytes:
    """Derive a deterministic 12-byte AES-GCM nonce from direction and counter."""
    if direction not in (_DIR_INIT_TO_RESP, _DIR_RESP_TO_INIT):
        raise ValueError("Invalid message direction")
    if counter < 1 or counter >= 1 << 64:
        raise ValueError("Counter out of valid range")
    return struct.pack(">IQ", direction, counter)


def _encode_header_aad(header: dict[str, Any]) -> bytes:
    """Serialize message header fields deterministically for use as AES-GCM AAD."""
    canonical = {
        "version": header["version"],
        "session_id": header["session_id"],
        "sender": header["sender"],
        "recipient": header["recipient"],
        "counter": header["counter"],
        "chunk_index": header["chunk_index"],
        "chunk_total": header["chunk_total"],
    }
    return json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _emit_event(
    log_event: LogEventCallback | None,
    *,
    node: str,
    actor: str,
    action: str,
    target: str,
    result: str,
    details: dict[str, Any] | None = None,
) -> None:
    """Invoke optional log_event callback without ever exposing keys or plaintext."""
    if log_event is None:
        return
    event = {
        "event_id": uuid.uuid4().hex,
        "ts": datetime.now(timezone.utc).isoformat(),
        "node": node,
        "actor": actor,
        "action": action,
        "target": target,
        "result": result,
        "details": details or {},
    }
    log_event(event)


def _resolve_state_file() -> Path:
    """Resolve the replay-state file path in MSG_STATE_DIR or the OS temp dir."""
    env_dir = os.environ.get("MSG_STATE_DIR", "").strip()
    state_dir = Path(env_dir).resolve() if env_dir else Path(tempfile.gettempdir()).resolve()
    if state_dir == _REPO_ROOT or _REPO_ROOT in state_dir.parents:
        raise ValueError("MSG_STATE_DIR must never point inside the repository directory")
    return state_dir / _STATE_FILENAME


def _load_persisted_state() -> dict[str, Any]:
    """Load persisted session IDs and seen counters from disk."""
    state_file = _resolve_state_file()
    if not state_file.exists():
        return {"sessions": {}}
    with state_file.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict) or not isinstance(data.get("sessions"), dict):
        return {"sessions": {}}
    return data


def _save_persisted_state(state: dict[str, Any]) -> None:
    """Atomically write only session IDs and seen counters via temp file + os.replace."""
    state_file = _resolve_state_file()
    state_dir = state_file.parent
    state_dir.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=".msg_state_", suffix=".tmp", dir=str(state_dir))
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(state, handle, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, state_file)
    except Exception:
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)
        raise


def _record_session_id(session_id: str) -> None:
    """Persist a known session_id with an empty counter map (no keys)."""
    state = _load_persisted_state()
    sessions = state.setdefault("sessions", {})
    if session_id not in sessions:
        sessions[session_id] = {"seen_counters": {}}
        _save_persisted_state(state)


def _has_seen_counter(session_id: str, receiver_scope: str, counter: int) -> bool:
    """Return True if counter was already recorded for this session and receiver scope."""
    state = _load_persisted_state()
    session_entry = state.get("sessions", {}).get(session_id, {})
    seen = session_entry.get("seen_counters", {}).get(receiver_scope, [])
    return counter in seen


def _mark_counter_seen(session_id: str, receiver_scope: str, counter: int) -> None:
    """Persist a verified message counter atomically."""
    state = _load_persisted_state()
    sessions = state.setdefault("sessions", {})
    session_entry = sessions.setdefault(session_id, {"seen_counters": {}})
    seen_map = session_entry.setdefault("seen_counters", {})
    counters = seen_map.setdefault(receiver_scope, [])
    if counter not in counters:
        counters.append(counter)
    _save_persisted_state(state)


def register_identity(user_id: str, sign_public_key: bytes) -> None:
    """Register an ML-DSA-65 identity verification public key for a user (in-memory stub)."""
    if not isinstance(user_id, str) or not user_id:
        raise ValueError("user_id must be a non-empty string")
    if not isinstance(sign_public_key, bytes) or len(sign_public_key) != ML_DSA_PUBLIC_KEY_SIZE:
        raise ValueError("sign_public_key must be a valid ML-DSA-65 public key")
    _PUBLIC_KEY_REGISTRY[user_id] = sign_public_key


def revoke_user(user_id: str) -> None:
    """Mark a user_id as revoked in the in-memory stub."""
    if not isinstance(user_id, str) or not user_id:
        raise ValueError("user_id must be a non-empty string")
    _REVOKED_USERS.add(user_id)


def clear_state_for_tests() -> None:
    """Close all active sessions and clear in-memory identity/revocation stubs."""
    for session in list(_ACTIVE_SESSIONS.values()):
        session.close()
    _ACTIVE_SESSIONS.clear()
    for pending in list(_PENDING_HANDSHAKES.values()):
        pending.clear_ephemeral_keys()
    _PENDING_HANDSHAKES.clear()
    _PUBLIC_KEY_REGISTRY.clear()
    _REVOKED_USERS.clear()


def get_public_keys(user_id: str) -> dict[str, bytes]:
    """Stub lookup returning the user's ML-DSA-65 signing public key.

    Identity keys are strictly limited to signing/verification (ML-DSA-65).
    """
    if user_id not in _PUBLIC_KEY_REGISTRY:
        raise KeyError(f"Unknown user_id: {user_id}")
    return {"ml_dsa_65_pk": _PUBLIC_KEY_REGISTRY[user_id]}


def is_revoked(user_id: str) -> bool:
    """Stub revocation check returning True if the user_id has been revoked."""
    return user_id in _REVOKED_USERS


def _extract_verify_key(
    user_id: str,
    lookup: PublicKeyLookup,
) -> bytes:
    """Extract ML-DSA-65 public verification key from get_public_keys()."""
    result = lookup(user_id)
    if isinstance(result, bytes):
        key = result
    elif isinstance(result, dict):
        key = (
            result.get("ml_dsa_65_pk")
            or result.get("sign_pk")
            or result.get("verify_key")
            or b""
        )
    else:
        raise SessionError(REASON_BAD_SIGNATURE, f"Invalid public key record for {user_id}")
    if not isinstance(key, bytes) or len(key) != ML_DSA_PUBLIC_KEY_SIZE:
        raise SessionError(REASON_BAD_SIGNATURE, f"Invalid ML-DSA-65 public key for {user_id}")
    return key


def _verify_peer_signature(
    peer_id: str,
    message: bytes,
    signature: bytes,
    lookup: PublicKeyLookup,
) -> None:
    """Verify peer ML-DSA-65 signature before touching any key-exchange material."""
    try:
        verify_pk = _extract_verify_key(peer_id, lookup)
        ok = ml_dsa_verify(verify_pk, message, signature)
    except SessionError:
        raise
    except Exception as exc:
        raise SessionError(REASON_BAD_SIGNATURE, f"Signature verification error for {peer_id}") from exc
    if not ok:
        raise SessionError(REASON_BAD_SIGNATURE, f"Invalid ML-DSA-65 signature from {peer_id}")


def _check_not_revoked(
    sender: str,
    recipient: str,
    revocation_fn: RevocationLookup,
) -> None:
    """Reject if either sender or recipient is revoked."""
    if revocation_fn(sender) or revocation_fn(recipient):
        raise SessionError(REASON_REVOKED, "Sender or recipient is revoked")


def initiate_handshake(
    sender: str,
    recipient: str,
    sender_sign_sk: bytes,
    *,
    session_id: str | None = None,
    get_public_keys_fn: PublicKeyLookup | None = None,
    is_revoked_fn: RevocationLookup | None = None,
    log_event: LogEventCallback | None = None,
) -> tuple[HandshakeInit, InitiatorHandshakeState]:
    """Create a signed ephemeral X25519 + ML-KEM-768 handshake initiation message.

    Args:
        sender: Initiator user ID.
        recipient: Responder user ID.
        sender_sign_sk: Initiator's ML-DSA-65 secret signing key.
        session_id: Optional explicit session identifier.
        get_public_keys_fn: Optional override for ``get_public_keys``.
        is_revoked_fn: Optional override for ``is_revoked``.
        log_event: Optional audit event callback.

    Returns:
        Tuple of ``(HandshakeInit, InitiatorHandshakeState)``.
    """
    del get_public_keys_fn  # Initiator uses its own signing key; responder verifies.
    rev_fn = is_revoked_fn or is_revoked
    sid = session_id or secrets.token_hex(16)

    try:
        _check_not_revoked(sender, recipient, rev_fn)
    except SessionError as exc:
        _emit_event(
            log_event,
            node=sender,
            actor=sender,
            action="handshake_init",
            target=sid,
            result="rejected",
            details={"reason_code": exc.reason_code, "peer": recipient},
        )
        raise

    eph_x25519_sk = x25519.X25519PrivateKey.generate()
    eph_x25519_pk = eph_x25519_sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    eph_kem_pk, eph_kem_sk = ml_kem_generate_keypair()

    init_body = _encode_init_body(
        PROTOCOL_VERSION,
        sid,
        sender,
        recipient,
        eph_x25519_pk,
        eph_kem_pk,
    )
    signature = ml_dsa_sign(sender_sign_sk, init_body)

    init_msg = HandshakeInit(
        version=PROTOCOL_VERSION,
        session_id=sid,
        sender=sender,
        recipient=recipient,
        x25519_pk=eph_x25519_pk,
        kem_pk=eph_kem_pk,
        signature=signature,
    )
    state = InitiatorHandshakeState(
        session_id=sid,
        sender=sender,
        recipient=recipient,
        eph_x25519_sk=eph_x25519_sk,
        eph_kem_sk=bytearray(eph_kem_sk),
        init_body=init_body,
        init_sig=signature,
    )
    _PENDING_HANDSHAKES[(sid, sender)] = state

    _emit_event(
        log_event,
        node=sender,
        actor=sender,
        action="handshake_init",
        target=sid,
        result="ok",
        details={"peer": recipient},
    )
    return init_msg, state


def respond_handshake(
    responder: str,
    responder_sign_sk: bytes,
    init_msg: HandshakeInit,
    *,
    get_public_keys_fn: PublicKeyLookup | None = None,
    is_revoked_fn: RevocationLookup | None = None,
    log_event: LogEventCallback | None = None,
) -> HandshakeResponse:
    """Verify initiator signature FIRST, encapsulate, and derive responder session keys."""
    pk_fn = get_public_keys_fn or get_public_keys
    rev_fn = is_revoked_fn or is_revoked
    sid = init_msg.session_id

    try:
        _check_not_revoked(init_msg.sender, responder, rev_fn)
        if init_msg.recipient != responder:
            raise SessionError(REASON_WRONG_RECIPIENT, "Handshake intended for another recipient")
        if init_msg.version != PROTOCOL_VERSION:
            raise SessionError(REASON_TAMPERED, "Unsupported protocol version")

        init_body = _encode_init_body(
            init_msg.version,
            sid,
            init_msg.sender,
            init_msg.recipient,
            init_msg.x25519_pk,
            init_msg.kem_pk,
        )
        # Mandatory: verify peer signature BEFORE using ephemeral X25519 or ML-KEM keys.
        _verify_peer_signature(init_msg.sender, init_body, init_msg.signature, pk_fn)

        if len(init_msg.x25519_pk) != _X25519_KEY_SIZE:
            raise SessionError(REASON_TAMPERED, "Invalid initiator X25519 public key length")
        if len(init_msg.kem_pk) != ML_KEM_PUBLIC_KEY_SIZE:
            raise SessionError(REASON_TAMPERED, "Invalid initiator ML-KEM-768 public key length")

        peer_x25519_pk = x25519.X25519PublicKey.from_public_bytes(init_msg.x25519_pk)
        kem_ct, kem_ss = ml_kem_encrypt(init_msg.kem_pk)
        resp_x25519_sk = x25519.X25519PrivateKey.generate()
        resp_x25519_pk = resp_x25519_sk.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        x25519_ss = resp_x25519_sk.exchange(peer_x25519_pk)
    except SessionError as exc:
        _emit_event(
            log_event,
            node=responder,
            actor=responder,
            action="handshake_respond",
            target=sid,
            result="rejected",
            details={"reason_code": exc.reason_code, "peer": init_msg.sender},
        )
        raise

    resp_body = _encode_resp_body(
        PROTOCOL_VERSION,
        sid,
        responder,
        init_msg.sender,
        kem_ct,
        resp_x25519_pk,
    )
    transcript = init_body + init_msg.signature + resp_body
    resp_sig = ml_dsa_sign(responder_sign_sk, transcript)

    i2r_key, r2i_key = _derive_directional_keys(x25519_ss, kem_ss, transcript)

    # Delete ephemeral private key and intermediate shared secrets immediately.
    del resp_x25519_sk, x25519_ss, kem_ss

    _ACTIVE_SESSIONS[(sid, responder)] = _EndpointSession(
        session_id=sid,
        owner=responder,
        peer=init_msg.sender,
        send_direction=_DIR_RESP_TO_INIT,
        recv_direction=_DIR_INIT_TO_RESP,
        send_key=r2i_key,
        recv_key=i2r_key,
    )
    _record_session_id(sid)

    _emit_event(
        log_event,
        node=responder,
        actor=responder,
        action="handshake_respond",
        target=sid,
        result="ok",
        details={"peer": init_msg.sender},
    )
    return HandshakeResponse(
        version=PROTOCOL_VERSION,
        session_id=sid,
        sender=responder,
        recipient=init_msg.sender,
        kem_ct=kem_ct,
        x25519_pk=resp_x25519_pk,
        signature=resp_sig,
    )


def complete_handshake(
    state: InitiatorHandshakeState,
    resp_msg: HandshakeResponse,
    *,
    get_public_keys_fn: PublicKeyLookup | None = None,
    is_revoked_fn: RevocationLookup | None = None,
    log_event: LogEventCallback | None = None,
) -> str:
    """Verify responder signature FIRST over full transcript and derive initiator keys."""
    pk_fn = get_public_keys_fn or get_public_keys
    rev_fn = is_revoked_fn or is_revoked
    sid = state.session_id

    try:
        _check_not_revoked(state.sender, state.recipient, rev_fn)
        if resp_msg.session_id != sid:
            raise SessionError(REASON_UNKNOWN_SESSION, "Handshake response session mismatch")
        if resp_msg.recipient != state.sender:
            raise SessionError(REASON_WRONG_RECIPIENT, "Handshake response addressed to wrong party")
        if resp_msg.sender != state.recipient:
            raise SessionError(REASON_WRONG_RECIPIENT, "Handshake response from unexpected sender")
        if resp_msg.version != PROTOCOL_VERSION:
            raise SessionError(REASON_TAMPERED, "Unsupported protocol version")

        resp_body = _encode_resp_body(
            resp_msg.version,
            sid,
            resp_msg.sender,
            resp_msg.recipient,
            resp_msg.kem_ct,
            resp_msg.x25519_pk,
        )
        transcript = state.init_body + state.init_sig + resp_body

        # Mandatory: verify peer signature BEFORE decapsulating or running X25519.
        _verify_peer_signature(resp_msg.sender, transcript, resp_msg.signature, pk_fn)

        if state.eph_x25519_sk is None or state.eph_kem_sk is None:
            raise SessionError(REASON_UNKNOWN_SESSION, "Ephemeral handshake keys already cleared")
        if len(resp_msg.kem_ct) != ML_KEM_CIPHERTEXT_SIZE:
            raise SessionError(REASON_TAMPERED, "Invalid ML-KEM-768 ciphertext length")
        if len(resp_msg.x25519_pk) != _X25519_KEY_SIZE:
            raise SessionError(REASON_TAMPERED, "Invalid responder X25519 public key length")

        kem_ss = ml_kem_decrypt(bytes(state.eph_kem_sk), resp_msg.kem_ct)
        peer_x25519_pk = x25519.X25519PublicKey.from_public_bytes(resp_msg.x25519_pk)
        x25519_ss = state.eph_x25519_sk.exchange(peer_x25519_pk)
    except SessionError as exc:
        _emit_event(
            log_event,
            node=state.sender,
            actor=state.sender,
            action="handshake_complete",
            target=sid,
            result="rejected",
            details={"reason_code": exc.reason_code, "peer": state.recipient},
        )
        raise

    i2r_key, r2i_key = _derive_directional_keys(x25519_ss, kem_ss, transcript)

    # Delete ephemeral private keys and intermediate shared secrets immediately.
    state.clear_ephemeral_keys()
    _PENDING_HANDSHAKES.pop((sid, state.sender), None)
    del x25519_ss, kem_ss

    _ACTIVE_SESSIONS[(sid, state.sender)] = _EndpointSession(
        session_id=sid,
        owner=state.sender,
        peer=state.recipient,
        send_direction=_DIR_INIT_TO_RESP,
        recv_direction=_DIR_RESP_TO_INIT,
        send_key=i2r_key,
        recv_key=r2i_key,
    )
    _record_session_id(sid)

    _emit_event(
        log_event,
        node=state.sender,
        actor=state.sender,
        action="handshake_complete",
        target=sid,
        result="ok",
        details={"peer": state.recipient},
    )
    return sid


def start_session(
    initiator: str,
    responder: str,
    initiator_sign_sk: bytes,
    responder_sign_sk: bytes,
    *,
    session_id: str | None = None,
    get_public_keys_fn: PublicKeyLookup | None = None,
    is_revoked_fn: RevocationLookup | None = None,
    log_event: LogEventCallback | None = None,
) -> str:
    """Establish an authenticated hybrid session between initiator and responder.

    Args:
        initiator: Initiator user ID.
        responder: Responder user ID.
        initiator_sign_sk: Initiator's ML-DSA-65 secret signing key.
        responder_sign_sk: Responder's ML-DSA-65 secret signing key.
        session_id: Optional explicit session ID.
        get_public_keys_fn: Optional override for ``get_public_keys``.
        is_revoked_fn: Optional override for ``is_revoked``.
        log_event: Optional audit event callback.

    Returns:
        The established ``session_id``.
    """
    init_msg, init_state = initiate_handshake(
        initiator,
        responder,
        initiator_sign_sk,
        session_id=session_id,
        get_public_keys_fn=get_public_keys_fn,
        is_revoked_fn=is_revoked_fn,
        log_event=log_event,
    )
    try:
        resp_msg = respond_handshake(
            responder,
            responder_sign_sk,
            init_msg,
            get_public_keys_fn=get_public_keys_fn,
            is_revoked_fn=is_revoked_fn,
            log_event=log_event,
        )
        sid = complete_handshake(
            init_state,
            resp_msg,
            get_public_keys_fn=get_public_keys_fn,
            is_revoked_fn=is_revoked_fn,
            log_event=log_event,
        )
    except Exception:
        init_state.clear_ephemeral_keys()
        _PENDING_HANDSHAKES.pop((init_state.session_id, initiator), None)
        raise

    _emit_event(
        log_event,
        node=initiator,
        actor=initiator,
        action="start_session",
        target=sid,
        result="ok",
        details={"peer": responder},
    )
    return sid


def send(
    session_id: str,
    sender: str,
    recipient: str,
    plaintext: bytes | str,
    *,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    is_revoked_fn: RevocationLookup | None = None,
    log_event: LogEventCallback | None = None,
) -> dict[str, Any] | list[dict[str, Any]]:
    """Encrypt plaintext with AES-256-GCM using directional keys and header AAD.

    Returns a single packet dict if the message fits in one chunk, or a list of
    packet dicts when chunked. Each chunk advances the monotonic counter so
    derived nonces are never reused.
    """
    if chunk_size < 1:
        raise ValueError("chunk_size must be at least 1")

    rev_fn = is_revoked_fn or is_revoked
    try:
        _check_not_revoked(sender, recipient, rev_fn)
    except SessionError as exc:
        _emit_event(
            log_event,
            node=sender,
            actor=sender,
            action="send",
            target=session_id,
            result="rejected",
            details={"reason_code": exc.reason_code, "recipient": recipient},
        )
        raise

    session = _ACTIVE_SESSIONS.get((session_id, sender))
    if session is None or session.send_key is None:
        exc = SessionError(REASON_UNKNOWN_SESSION, f"Unknown or closed session {session_id}")
        _emit_event(
            log_event,
            node=sender,
            actor=sender,
            action="send",
            target=session_id,
            result="rejected",
            details={"reason_code": exc.reason_code, "recipient": recipient},
        )
        raise exc

    if session.peer != recipient:
        exc = SessionError(REASON_WRONG_RECIPIENT, f"Session {session_id} is not addressed to {recipient}")
        _emit_event(
            log_event,
            node=sender,
            actor=sender,
            action="send",
            target=session_id,
            result="rejected",
            details={"reason_code": exc.reason_code, "recipient": recipient},
        )
        raise exc

    data = plaintext.encode("utf-8") if isinstance(plaintext, str) else bytes(plaintext)
    if not data:
        chunks = [b""]
    else:
        chunks = [data[i : i + chunk_size] for i in range(0, len(data), chunk_size)]

    total = len(chunks)
    aesgcm = AESGCM(bytes(session.send_key))
    packets: list[dict[str, Any]] = []

    for idx, chunk in enumerate(chunks):
        session.send_counter += 1
        counter = session.send_counter
        header = {
            "version": PROTOCOL_VERSION,
            "session_id": session_id,
            "sender": sender,
            "recipient": recipient,
            "counter": counter,
            "chunk_index": idx,
            "chunk_total": total,
        }
        aad = _encode_header_aad(header)
        nonce = _derive_nonce(session.send_direction, counter)
        ciphertext = aesgcm.encrypt(nonce, chunk, aad)
        packets.append(
            {
                "header": header,
                "nonce": base64.b64encode(nonce).decode("ascii"),
                "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            }
        )

    _emit_event(
        log_event,
        node=sender,
        actor=sender,
        action="send",
        target=session_id,
        result="ok",
        details={"recipient": recipient, "chunks": total},
    )
    return packets[0] if total == 1 else packets


def _session_exists_for_other_party(session_id: str, recipient: str) -> bool:
    return any(sid == session_id and owner != recipient for sid, owner in _ACTIVE_SESSIONS)


def _receive_single_packet(
    session_id: str,
    recipient: str,
    packet: dict[str, Any],
    *,
    is_revoked_fn: RevocationLookup | None = None,
    log_event: LogEventCallback | None = None,
) -> bytes | None:
    rev_fn = is_revoked_fn or is_revoked

    try:
        if not isinstance(packet, dict):
            raise SessionError(REASON_TAMPERED, "Malformed packet")
        header = packet.get("header")
        if not isinstance(header, dict):
            raise SessionError(REASON_TAMPERED, "Missing packet header")

        required_fields = (
            "version",
            "session_id",
            "sender",
            "recipient",
            "counter",
            "chunk_index",
            "chunk_total",
        )
        if any(field_name not in header for field_name in required_fields):
            raise SessionError(REASON_TAMPERED, "Incomplete packet header")

        hdr_sid = header["session_id"]
        hdr_sender = header["sender"]
        hdr_recipient = header["recipient"]
        hdr_version = header["version"]
        counter = header["counter"]
        chunk_index = header["chunk_index"]
        chunk_total = header["chunk_total"]

        if hdr_sid != session_id:
            raise SessionError(REASON_UNKNOWN_SESSION, "Packet session_id does not match target session")

        session = _ACTIVE_SESSIONS.get((session_id, recipient))
        if session is None or session.recv_key is None:
            if _session_exists_for_other_party(session_id, recipient) and hdr_recipient != recipient:
                raise SessionError(REASON_WRONG_RECIPIENT, "Packet recipient does not match receiver")
            raise SessionError(REASON_UNKNOWN_SESSION, f"Unknown or closed session {session_id}")

        if not isinstance(hdr_sender, str) or not isinstance(hdr_recipient, str):
            raise SessionError(REASON_TAMPERED, "Invalid sender or recipient field")

        _check_not_revoked(hdr_sender, recipient, rev_fn)

        if hdr_recipient != recipient or hdr_sender != session.peer:
            raise SessionError(REASON_WRONG_RECIPIENT, "Packet addressed to wrong recipient or unexpected sender")

        if (
            not isinstance(hdr_version, int)
            or isinstance(hdr_version, bool)
            or hdr_version != PROTOCOL_VERSION
        ):
            raise SessionError(REASON_TAMPERED, "Invalid protocol version")

        if (
            not isinstance(counter, int)
            or isinstance(counter, bool)
            or counter < 1
            or not isinstance(chunk_index, int)
            or isinstance(chunk_index, bool)
            or not isinstance(chunk_total, int)
            or isinstance(chunk_total, bool)
            or chunk_total < 1
            or chunk_index < 0
            or chunk_index >= chunk_total
        ):
            raise SessionError(REASON_TAMPERED, "Invalid counter or chunk metadata")

        receiver_scope = f"{recipient}:{session.recv_direction}"
        if _has_seen_counter(session_id, receiver_scope, counter):
            raise SessionError(REASON_REPLAY, f"Replayed message counter {counter}")

        nonce_b64 = packet.get("nonce")
        ct_b64 = packet.get("ciphertext")
        if not isinstance(nonce_b64, str) or not isinstance(ct_b64, str):
            raise SessionError(REASON_TAMPERED, "Missing nonce or ciphertext")

        try:
            wire_nonce = base64.b64decode(nonce_b64, validate=True)
            ciphertext = base64.b64decode(ct_b64, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise SessionError(REASON_TAMPERED, "Invalid Base64 encoding") from exc

        expected_nonce = _derive_nonce(session.recv_direction, counter)
        if wire_nonce != expected_nonce:
            raise SessionError(REASON_TAMPERED, "Nonce mismatch")

        aad = _encode_header_aad(header)
        try:
            plaintext = AESGCM(bytes(session.recv_key)).decrypt(expected_nonce, ciphertext, aad)
        except InvalidTag as exc:
            raise SessionError(REASON_TAMPERED, "Ciphertext or header authentication failed") from exc

        _mark_counter_seen(session_id, receiver_scope, counter)

        if chunk_total == 1:
            result_bytes: bytes | None = plaintext
        else:
            base_counter = counter - chunk_index
            buf_key = (hdr_sender, base_counter, chunk_total)
            chunk_map = session.chunk_buffers.setdefault(buf_key, {})
            chunk_map[chunk_index] = plaintext
            if len(chunk_map) == chunk_total:
                completed = b"".join(chunk_map[i] for i in range(chunk_total))
                session.chunk_buffers.pop(buf_key, None)
                result_bytes = completed
            else:
                result_bytes = None
    except SessionError as exc:
        _emit_event(
            log_event,
            node=recipient,
            actor=recipient,
            action="receive",
            target=session_id,
            result="rejected",
            details={"reason_code": exc.reason_code},
        )
        raise

    _emit_event(
        log_event,
        node=recipient,
        actor=recipient,
        action="receive",
        target=session_id,
        result="ok",
        details={"counter": counter, "chunk_index": chunk_index, "chunk_total": chunk_total},
    )
    return result_bytes


def receive(
    session_id: str,
    recipient: str,
    packet: dict[str, Any] | list[dict[str, Any]],
    *,
    is_revoked_fn: RevocationLookup | None = None,
    log_event: LogEventCallback | None = None,
) -> bytes | None:
    """Verify, decrypt, and replay-check one packet or a list of chunked packets."""
    if isinstance(packet, list):
        if not packet:
            raise SessionError(REASON_TAMPERED, "Empty packet list")
        output: bytes | None = None
        for item in packet:
            output = _receive_single_packet(
                session_id,
                recipient,
                item,
                is_revoked_fn=is_revoked_fn,
                log_event=log_event,
            )
        return output

    return _receive_single_packet(
        session_id,
        recipient,
        packet,
        is_revoked_fn=is_revoked_fn,
        log_event=log_event,
    )


def close_session(
    session_id: str,
    actor: str | None = None,
    *,
    log_event: LogEventCallback | None = None,
) -> None:
    """Delete all in-memory session keys and pending ephemeral keys for a session.

    Persisted replay-protection state (session IDs and seen counters) is left
    intact and never contains cryptographic keys.
    """
    closed_actors: list[str] = []
    for key in list(_ACTIVE_SESSIONS.keys()):
        sid, owner = key
        if sid == session_id and (actor is None or owner == actor):
            session = _ACTIVE_SESSIONS.pop(key)
            session.close()
            closed_actors.append(owner)

    for key in list(_PENDING_HANDSHAKES.keys()):
        sid, owner = key
        if sid == session_id and (actor is None or owner == actor):
            pending = _PENDING_HANDSHAKES.pop(key)
            pending.clear_ephemeral_keys()
            if owner not in closed_actors:
                closed_actors.append(owner)

    _emit_event(
        log_event,
        node=actor or "messaging.session",
        actor=actor or "system",
        action="close_session",
        target=session_id,
        result="ok",
        details={"closed_actors": sorted(closed_actors)},
    )
