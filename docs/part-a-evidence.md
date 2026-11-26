# Part A Evidence & Security Summary

## 1. Goal Verification Matrix

| Goal | Status | Proving Test(s) | How It Works |
| :--- | :--- | :--- | :--- |
| Replay rejection | implemented | `test_replay_rejected`, `test_duplicate_chunk_ignored_and_message_completes` | Each authenticated packet's `(session_id, receiver_scope, counter)` is checked against and atomically persisted to `messaging_replay_state.json`, rejecting previously seen counters with `FAILED` (`REPLAY`). |
| Recipient binding | implemented | `test_changed_recipient_rejected`, `test_eavesdropper_cannot_decrypt` | Handshake messages sign `sender` and `recipient` with ML-DSA-65 and bind them into the HKDF transcript, while `receive()` checks header `recipient`/`sender` against the active session and verifies the header as AES-256-GCM AAD. |
| Forward secrecy | implemented | `test_old_session_unreadable_after_identity_key_leaks` | Session keys are derived via HKDF-SHA256 from fresh ephemeral X25519 and ML-KEM-768 shared secrets whose private keys are cleared immediately after the handshake, and `close_session()` zeroes symmetric keys in memory so later identity key theft cannot decrypt past traffic. |
| Delivery under loss/reordering | implemented | `test_shuffled_chunks_delivered_correctly`, `test_one_dropped_chunk_fails_after_expire_incomplete`, `test_duplicate_chunk_ignored_and_message_completes`, `test_chunked_round_trip_uses_unique_nonces` | Receivers authenticate each chunk on arrival, buffer out-of-order chunks by `(session_id, msg_id)` and `chunk_index` until complete, ignore duplicate in-flight chunks (`DUPLICATE_CHUNK`), and expire incomplete messages after timeout via `expire_incomplete()` (`INCOMPLETE_TIMEOUT`). |
| `protected_read` interoperability | implemented | `test_protected_read_round_trip`, `test_protected_read_proof_is_lowercase_hex_64`, `test_protected_read_non_ascii_utf8`, `test_protected_read_invalid_key_returns_none`, `test_protected_read_invalid_message_inputs_return_none` | `protected_read()` validates a standard Base64 1184-byte ML-KEM-768 public key, encapsulates a shared secret, and returns Base64 `ciphertext` plus a lowercase 64-hex HMAC-SHA256 `proof` over `(challenge + body).encode("utf-8")` (or `None` on failure). |
| Session resumption | not implemented | None | Active symmetric keys are held solely in memory (`_ACTIVE_SESSIONS`) and are never written to disk, so sessions cannot resume after `close_session()` or process restarts. |

## 2. Limits of Part A

- **Forward secrecy scope (no per-message ratcheting):** Post-handshake compromise of long-term ML-DSA-65 signing keys cannot decrypt recorded sessions, and `close_session()` zeroes symmetric keys; however, keys do not ratchet per message, so compromising an active session's in-memory keys before `close_session()` exposes traffic in that session.
- **Pre-handshake / in-flight key compromise:** Compromising a party's ML-DSA-65 signing key before or during a handshake allows an active person-in-the-middle attacker to impersonate that identity on new or in-flight handshakes.
- **Python and OS memory retention:** Ephemeral ML-KEM secret keys and session keys use best-effort `bytearray` zeroing and `del`, which cannot prevent immutable Python `bytes` copies, garbage-collection lag, OS swap, or core dumps from retaining key material.
- **Metadata visible on the wire:** Packet `header` fields (`version`, `session_id`, `msg_id`, `sender`, `recipient`, `counter`, `chunk_index`, `chunk_total`) and `nonce`, as well as handshake identities and signatures, are sent unencrypted; chunk counts and ciphertext sizes remain observable.
- **Endpoints and local stubs assumed uncompromised:** Endpoints are trusted after decryption/delivery; identity lookup (`_PUBLIC_KEY_REGISTRY`) and revocation (`_REVOKED_USERS`) are in-memory stubs without persistent PKI/CRL distribution, and `MSG_STATE_DIR` replay state (`messaging_replay_state.json`) is stored unencrypted on local disk with an unbounded list of seen counters per session.
- **Manual expiration & bounded buffering:** Incomplete chunked messages rely on callers invoking `expire_incomplete()`, subject to fixed default limits (`DEFAULT_MAX_CHUNKS_PER_MESSAGE = 64`, `DEFAULT_MAX_PENDING_MESSAGES = 32`, `DEFAULT_REASSEMBLY_TIMEOUT_SECONDS = 30.0`).
- **Unaudited prototype:** `messaging/session.py` and `messaging/protected_read.py` constitute a prototype and have not undergone a formal cryptographic or security audit (and `protected_read()` does not itself authenticate the caller-supplied ML-KEM-768 public key).

## 3. Threat Model Summary (Part A)

Part A protects message payloads, directional AES-256-GCM session keys, and `protected_read` HMAC proofs against passive eavesdroppers, active packet tamperers/replayers, and attackers who steal long-term ML-DSA-65 identity keys after a handshake completes. It assumes uncompromised endpoints, authentic out-of-band identity key distribution/revocation, and protected local replay-state storage (`MSG_STATE_DIR`). Security is bounded by visible wire metadata (sender, recipient, session/message IDs, counters, chunk counts), lack of per-message ratcheting while a session remains open in memory, Python/OS memory retention beyond best-effort `bytearray` zeroing, no session resumption, and the fact that this prototype is unaudited.

## 4. Verification Runs

- `python -m pytest -q`: **54 passed in 1.71s**
- `python -m messaging.demo_part_a`:

```text
1. Handshake + round trip Alice->Bob: DELIVERED (20 bytes)
2. Replayed message: FAILED -> REPLAY
3. Changed recipient: FAILED -> WRONG_RECIPIENT
4. Flipped byte: FAILED -> TAMPERED
5. Shuffled chunks (5 chunks): DELIVERED (39 bytes)
6. Dropped chunk after expire_incomplete: FAILED -> INCOMPLETE_TIMEOUT
7. Old session after identity key leak: UNREADABLE (UNKNOWN_SESSION, offline InvalidTag)
```
