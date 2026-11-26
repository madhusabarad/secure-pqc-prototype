## Setup

Requires Python 3.12:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m pytest -q
```

## Part A: Secure messaging

`messaging/session.py` implements an authenticated hybrid key exchange (ML-DSA-65 identity signatures over ephemeral X25519 + ML-KEM-768 keys) and directional AES-256-GCM message transport with HKDF-SHA256 key derivation, header AAD binding, monotonic counter nonces, replay detection backed by `MSG_STATE_DIR` (persisting only session IDs and seen counters, never keys), and out-of-order chunk reassembly with timeout expiration via `expire_incomplete()`. `messaging/protected_read.py` provides ML-KEM-768 encapsulation and HMAC-SHA256 proof generation for protected reads.

Run the Part A tests and demo:

```bash
python -m pytest -q tests/test_messaging_session.py tests/test_messaging_chunks.py tests/test_messaging_protected_read.py
python -m messaging.demo_part_a
```

Functions for callers:
- `messaging.session`: `register_identity`, `revoke_user`, `get_public_keys`, `is_revoked`, `initiate_handshake`, `respond_handshake`, `complete_handshake`, `start_session`, `send`, `receive`, `expire_incomplete`, `close_session` (plus `clear_state_for_tests` for test isolation)
- `messaging.protected_read`: `protected_read`

### Limits of Part A

Active sessions, pending handshakes, identity keys, and revocation flags live only in process memory (`_ACTIVE_SESSIONS`, `_PENDING_HANDSHAKES`, `_PUBLIC_KEY_REGISTRY`, `_REVOKED_USERS`), and session resumption is not implemented—calling `close_session()` or restarting the process discards all symmetric keys and requires a new handshake. Within an active session, keys do not ratchet per message, so process-memory compromise before `close_session()` exposes messages in that active session (whereas post-handshake leakage of long-term ML-DSA-65 signing keys cannot decrypt closed or previously recorded sessions). Compromising ML-DSA-65 signing keys before or during a handshake permits active impersonation on new or in-flight handshakes, best-effort `bytearray` zeroing cannot erase immutable Python `bytes` copies or OS swap/core dumps, and replay state (`messaging_replay_state.json`) is local to `MSG_STATE_DIR` rather than replicated across nodes.

## Credits

Adapter starters and the validator come from the official Track 4 Toolkit (`ScalerOpenSourceLabs/Track-4-Toolkit`).
