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
import time
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
DEFAULT_REASSEMBLY_TIMEOUT_SECONDS = 30.0
DEFAULT_MAX_CHUNKS_PER_MESSAGE = 64
DEFAULT_MAX_PENDING_MESSAGES = 32
_MAX_FAILED_MSG_HISTORY = 256
_X25519_KEY_SIZE = 32
_AES_256_KEY_SIZE = 32
_DIR_INIT_TO_RESP = 0
_DIR_RESP_TO_INIT = 1
_INIT_TAG = b"PQC-MSG-V1-INIT"
_RESP_TAG = b"PQC-MSG-V1-RESP"
_REPO_ROOT = Path(__file__).resolve().parent.parent
_STATE_FILENAME = "messaging_replay_state.json"

STATUS_DELIVERED = "DELIVERED"
STATUS_PENDING = "PENDING"
STATUS_FAILED = "FAILED"

REASON_REPLAY = "REPLAY"
REASON_WRONG_RECIPIENT = "WRONG_RECIPIENT"
REASON_TAMPERED = "TAMPERED"
REASON_UNKNOWN_SESSION = "UNKNOWN_SESSION"
REASON_BAD_SIGNATURE = "BAD_SIGNATURE"
REASON_REVOKED = "REVOKED"
REASON_DUPLICATE_CHUNK = "DUPLICATE_CHUNK"
REASON_INCONSISTENT_CHUNKS = "INCONSISTENT_CHUNKS"
REASON_INCOMPLETE_TIMEOUT = "INCOMPLETE_TIMEOUT"
REASON_TOO_LARGE = "TOO_LARGE"
REASON_BUFFER_FULL = "BUFFER_FULL"

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


@dataclass(frozen=True)
class ReceiveResult:
    """Result returned by ``receive()`` and ``expire_incomplete()``."""

    status: str
    reason_code: str | None = None
    plaintext: bytes | None = None
    session_id: str | None = None
    msg_id: str | None = None


@dataclass
class _ChunkBuffer:
    """Pending authenticated chunks for a single in-flight message."""

    session_id: str
    msg_id: str
    sender: str
    chunk_total: int
    created_at: float
    timeout: float
    chunks: dict[int, bytes] = field(default_factory=dict)


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
    chunk_buffers: dict[tuple[str, str], _ChunkBuffer] = field(default_factory=dict)
    failed_msgs: dict[str, str] = field(default_factory=dict)

    def record_failed_msg(self, msg_id: str, reason_code: str) -> None:
        """Remember a failed msg_id (bounded) so late chunks are rejected without buffering."""
        self.failed_msgs[msg_id] = reason_code
        while len(self.failed_msgs) > _MAX_FAILED_MSG_HISTORY:
            oldest_key = next(iter(self.failed_msgs))
            self.failed_msgs.pop(oldest_key, None)

    def close(self) -> None:
        """Zero and delete symmetric session keys from memory."""
        if self.send_key is not None:
            _wipe_bytearray(self.send_key)
            self.send_key = None
        if self.recv_key is not None:
            _wipe_bytearray(self.recv_key)
            self.recv_key = None
        self.chunk_buffers.clear()
        self.failed_msgs.clear()


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
        "msg_id": header["msg_id"],
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
    msg_id: str | None = None,
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
    if msg_id is not None and (not isinstance(msg_id, str) or not msg_id):
        raise ValueError("msg_id must be a non-empty string")
    message_id = msg_id or secrets.token_hex(16)

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
            "msg_id": message_id,
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
        details={"recipient": recipient, "msg_id": message_id, "chunks": total},
    )
    return packets[0] if total == 1 else packets


def _session_exists_for_other_party(session_id: str, recipient: str) -> bool:
    return any(sid == session_id and owner != recipient for sid, owner in _ACTIVE_SESSIONS)


def _fail_receive(
    reason_code: str,
    *,
    session_id: str,
    recipient: str,
    msg_id: str | None = None,
    log_event: LogEventCallback | None = None,
) -> ReceiveResult:
    """Emit a FAILED audit event (without plaintext or keys) and build a FAILED result."""
    details: dict[str, Any] = {"reason_code": reason_code}
    if msg_id is not None:
        details["msg_id"] = msg_id
    _emit_event(
        log_event,
        node=recipient,
        actor=recipient,
        action="receive",
        target=session_id,
        result=STATUS_FAILED,
        details=details,
    )
    return ReceiveResult(
        status=STATUS_FAILED,
        reason_code=reason_code,
        plaintext=None,
        session_id=session_id,
        msg_id=msg_id,
    )


def _deliver_receive(
    plaintext: bytes,
    *,
    session_id: str,
    recipient: str,
    msg_id: str,
    chunk_total: int,
    counter: int,
    log_event: LogEventCallback | None = None,
) -> ReceiveResult:
    """Emit a DELIVERED audit event (without plaintext or keys) and build a DELIVERED result."""
    _emit_event(
        log_event,
        node=recipient,
        actor=recipient,
        action="receive",
        target=session_id,
        result=STATUS_DELIVERED,
        details={"msg_id": msg_id, "chunk_total": chunk_total, "counter": counter},
    )
    return ReceiveResult(
        status=STATUS_DELIVERED,
        reason_code=None,
        plaintext=plaintext,
        session_id=session_id,
        msg_id=msg_id,
    )


def _receive_single_packet(
    session_id: str,
    recipient: str,
    packet: dict[str, Any],
    *,
    now: float | None = None,
    max_chunks: int = DEFAULT_MAX_CHUNKS_PER_MESSAGE,
    max_pending: int = DEFAULT_MAX_PENDING_MESSAGES,
    reassembly_timeout: float = DEFAULT_REASSEMBLY_TIMEOUT_SECONDS,
    is_revoked_fn: RevocationLookup | None = None,
    log_event: LogEventCallback | None = None,
) -> ReceiveResult:
    rev_fn = is_revoked_fn or is_revoked

    if not isinstance(packet, dict):
        return _fail_receive(REASON_TAMPERED, session_id=session_id, recipient=recipient, log_event=log_event)
    header = packet.get("header")
    if not isinstance(header, dict):
        return _fail_receive(REASON_TAMPERED, session_id=session_id, recipient=recipient, log_event=log_event)

    hdr_sid = header.get("session_id")
    hdr_recipient = header.get("recipient")
    if hdr_sid != session_id:
        return _fail_receive(REASON_UNKNOWN_SESSION, session_id=session_id, recipient=recipient, log_event=log_event)

    session = _ACTIVE_SESSIONS.get((session_id, recipient))
    if session is None or session.recv_key is None:
        if _session_exists_for_other_party(session_id, recipient) and hdr_recipient != recipient:
            return _fail_receive(REASON_WRONG_RECIPIENT, session_id=session_id, recipient=recipient, log_event=log_event)
        return _fail_receive(REASON_UNKNOWN_SESSION, session_id=session_id, recipient=recipient, log_event=log_event)

    required_fields = (
        "version",
        "session_id",
        "msg_id",
        "sender",
        "recipient",
        "counter",
        "chunk_index",
        "chunk_total",
    )
    if any(field_name not in header for field_name in required_fields):
        return _fail_receive(REASON_TAMPERED, session_id=session_id, recipient=recipient, log_event=log_event)

    hdr_msg_id = header["msg_id"]
    hdr_sender = header["sender"]
    hdr_version = header["version"]
    counter = header["counter"]
    chunk_index = header["chunk_index"]
    chunk_total = header["chunk_total"]

    if not isinstance(hdr_msg_id, str) or not hdr_msg_id:
        return _fail_receive(REASON_TAMPERED, session_id=session_id, recipient=recipient, log_event=log_event)
    if not isinstance(hdr_sender, str) or not isinstance(hdr_recipient, str):
        return _fail_receive(REASON_TAMPERED, session_id=session_id, recipient=recipient, msg_id=hdr_msg_id, log_event=log_event)

    try:
        _check_not_revoked(hdr_sender, recipient, rev_fn)
    except SessionError as exc:
        return _fail_receive(exc.reason_code, session_id=session_id, recipient=recipient, msg_id=hdr_msg_id, log_event=log_event)

    if hdr_recipient != recipient or hdr_sender != session.peer:
        return _fail_receive(REASON_WRONG_RECIPIENT, session_id=session_id, recipient=recipient, msg_id=hdr_msg_id, log_event=log_event)

    if (
        not isinstance(hdr_version, int)
        or isinstance(hdr_version, bool)
        or hdr_version != PROTOCOL_VERSION
    ):
        return _fail_receive(REASON_TAMPERED, session_id=session_id, recipient=recipient, msg_id=hdr_msg_id, log_event=log_event)

    if (
        not isinstance(counter, int)
        or isinstance(counter, bool)
        or counter < 1
        or not isinstance(chunk_index, int)
        or isinstance(chunk_index, bool)
        or not isinstance(chunk_total, int)
        or isinstance(chunk_total, bool)
    ):
        return _fail_receive(REASON_TAMPERED, session_id=session_id, recipient=recipient, msg_id=hdr_msg_id, log_event=log_event)

    nonce_b64 = packet.get("nonce")
    ct_b64 = packet.get("ciphertext")
    if not isinstance(nonce_b64, str) or not isinstance(ct_b64, str):
        return _fail_receive(REASON_TAMPERED, session_id=session_id, recipient=recipient, msg_id=hdr_msg_id, log_event=log_event)

    try:
        wire_nonce = base64.b64decode(nonce_b64, validate=True)
        ciphertext = base64.b64decode(ct_b64, validate=True)
    except (binascii.Error, ValueError):
        return _fail_receive(REASON_TAMPERED, session_id=session_id, recipient=recipient, msg_id=hdr_msg_id, log_event=log_event)

    expected_nonce = _derive_nonce(session.recv_direction, counter)
    if wire_nonce != expected_nonce:
        return _fail_receive(REASON_TAMPERED, session_id=session_id, recipient=recipient, msg_id=hdr_msg_id, log_event=log_event)

    # Authenticate chunk on arrival (header is AAD); invalid chunks are dropped and never buffered.
    aad = _encode_header_aad(header)
    try:
        plaintext = AESGCM(bytes(session.recv_key)).decrypt(expected_nonce, ciphertext, aad)
    except InvalidTag:
        return _fail_receive(REASON_TAMPERED, session_id=session_id, recipient=recipient, msg_id=hdr_msg_id, log_event=log_event)

    receiver_scope = f"{recipient}:{session.recv_direction}"
    buf_key = (session_id, hdr_msg_id)
    existing_buf = session.chunk_buffers.get(buf_key)

    if existing_buf is not None:
        if (
            chunk_total != existing_buf.chunk_total
            or chunk_index < 0
            or chunk_index >= existing_buf.chunk_total
            or hdr_sender != existing_buf.sender
        ):
            session.chunk_buffers.pop(buf_key, None)
            existing_buf.chunks.clear()
            session.record_failed_msg(hdr_msg_id, REASON_INCONSISTENT_CHUNKS)
            return _fail_receive(
                REASON_INCONSISTENT_CHUNKS,
                session_id=session_id,
                recipient=recipient,
                msg_id=hdr_msg_id,
                log_event=log_event,
            )

        if chunk_index in existing_buf.chunks:
            if not _has_seen_counter(session_id, receiver_scope, counter):
                _mark_counter_seen(session_id, receiver_scope, counter)
            return ReceiveResult(
                status=STATUS_PENDING,
                reason_code=REASON_DUPLICATE_CHUNK,
                plaintext=None,
                session_id=session_id,
                msg_id=hdr_msg_id,
            )

        if _has_seen_counter(session_id, receiver_scope, counter):
            return _fail_receive(REASON_REPLAY, session_id=session_id, recipient=recipient, msg_id=hdr_msg_id, log_event=log_event)

        _mark_counter_seen(session_id, receiver_scope, counter)
        existing_buf.chunks[chunk_index] = plaintext
        if len(existing_buf.chunks) == existing_buf.chunk_total:
            completed = b"".join(existing_buf.chunks[i] for i in range(existing_buf.chunk_total))
            session.chunk_buffers.pop(buf_key, None)
            existing_buf.chunks.clear()
            return _deliver_receive(
                completed,
                session_id=session_id,
                recipient=recipient,
                msg_id=hdr_msg_id,
                chunk_total=chunk_total,
                counter=counter,
                log_event=log_event,
            )
        return ReceiveResult(
            status=STATUS_PENDING,
            reason_code=None,
            plaintext=None,
            session_id=session_id,
            msg_id=hdr_msg_id,
        )

    if _has_seen_counter(session_id, receiver_scope, counter):
        return _fail_receive(REASON_REPLAY, session_id=session_id, recipient=recipient, msg_id=hdr_msg_id, log_event=log_event)

    if hdr_msg_id in session.failed_msgs:
        return _fail_receive(
            session.failed_msgs[hdr_msg_id],
            session_id=session_id,
            recipient=recipient,
            msg_id=hdr_msg_id,
            log_event=log_event,
        )

    if chunk_total < 1 or chunk_index < 0 or chunk_index >= chunk_total:
        session.record_failed_msg(hdr_msg_id, REASON_INCONSISTENT_CHUNKS)
        return _fail_receive(
            REASON_INCONSISTENT_CHUNKS,
            session_id=session_id,
            recipient=recipient,
            msg_id=hdr_msg_id,
            log_event=log_event,
        )

    if chunk_total > max_chunks:
        return _fail_receive(REASON_TOO_LARGE, session_id=session_id, recipient=recipient, msg_id=hdr_msg_id, log_event=log_event)

    if chunk_total == 1:
        _mark_counter_seen(session_id, receiver_scope, counter)
        return _deliver_receive(
            plaintext,
            session_id=session_id,
            recipient=recipient,
            msg_id=hdr_msg_id,
            chunk_total=chunk_total,
            counter=counter,
            log_event=log_event,
        )

    if len(session.chunk_buffers) >= max_pending:
        return _fail_receive(REASON_BUFFER_FULL, session_id=session_id, recipient=recipient, msg_id=hdr_msg_id, log_event=log_event)

    _mark_counter_seen(session_id, receiver_scope, counter)
    current_now = time.monotonic() if now is None else float(now)
    session.chunk_buffers[buf_key] = _ChunkBuffer(
        session_id=session_id,
        msg_id=hdr_msg_id,
        sender=hdr_sender,
        chunk_total=chunk_total,
        created_at=current_now,
        timeout=float(reassembly_timeout),
        chunks={chunk_index: plaintext},
    )
    return ReceiveResult(
        status=STATUS_PENDING,
        reason_code=None,
        plaintext=None,
        session_id=session_id,
        msg_id=hdr_msg_id,
    )


def expire_incomplete(
    now: float | None = None,
    *,
    session_id: str | None = None,
    recipient: str | None = None,
    timeout: float | None = None,
    log_event: LogEventCallback | None = None,
) -> list[ReceiveResult]:
    """Discard incomplete buffered messages older than the configured timeout."""
    if timeout is not None and timeout < 0:
        raise ValueError("timeout must be non-negative")
    current_now = time.monotonic() if now is None else float(now)
    expired_results: list[ReceiveResult] = []

    for (sid, owner), session in list(_ACTIVE_SESSIONS.items()):
        if session_id is not None and sid != session_id:
            continue
        if recipient is not None and owner != recipient:
            continue
        for buf_key in list(session.chunk_buffers.keys()):
            buf = session.chunk_buffers[buf_key]
            effective_timeout = buf.timeout if timeout is None else float(timeout)
            if current_now - buf.created_at >= effective_timeout:
                session.chunk_buffers.pop(buf_key, None)
                buf.chunks.clear()
                session.record_failed_msg(buf.msg_id, REASON_INCOMPLETE_TIMEOUT)
                _emit_event(
                    log_event,
                    node=owner,
                    actor=owner,
                    action="receive",
                    target=sid,
                    result=STATUS_FAILED,
                    details={"reason_code": REASON_INCOMPLETE_TIMEOUT, "msg_id": buf.msg_id},
                )
                expired_results.append(
                    ReceiveResult(
                        status=STATUS_FAILED,
                        reason_code=REASON_INCOMPLETE_TIMEOUT,
                        plaintext=None,
                        session_id=sid,
                        msg_id=buf.msg_id,
                    )
                )

    return expired_results


def receive(
    session_id: str,
    recipient: str,
    packet: dict[str, Any] | list[dict[str, Any]],
    *,
    now: float | None = None,
    max_chunks: int = DEFAULT_MAX_CHUNKS_PER_MESSAGE,
    max_pending: int = DEFAULT_MAX_PENDING_MESSAGES,
    reassembly_timeout: float = DEFAULT_REASSEMBLY_TIMEOUT_SECONDS,
    is_revoked_fn: RevocationLookup | None = None,
    log_event: LogEventCallback | None = None,
) -> ReceiveResult:
    """Verify, decrypt, replay-check, and reassemble one packet or a list of packets."""
    if max_chunks < 1:
        raise ValueError("max_chunks must be at least 1")
    if max_pending < 1:
        raise ValueError("max_pending must be at least 1")
    if reassembly_timeout < 0:
        raise ValueError("reassembly_timeout must be non-negative")

    if isinstance(packet, list):
        if not packet:
            return _fail_receive(REASON_TAMPERED, session_id=session_id, recipient=recipient, log_event=log_event)
        last_result: ReceiveResult | None = None
        for item in packet:
            last_result = _receive_single_packet(
                session_id,
                recipient,
                item,
                now=now,
                max_chunks=max_chunks,
                max_pending=max_pending,
                reassembly_timeout=reassembly_timeout,
                is_revoked_fn=is_revoked_fn,
                log_event=log_event,
            )
            if last_result.status == STATUS_FAILED:
                return last_result
        assert last_result is not None
        return last_result

    return _receive_single_packet(
        session_id,
        recipient,
        packet,
        now=now,
        max_chunks=max_chunks,
        max_pending=max_pending,
        reassembly_timeout=reassembly_timeout,
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
