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

## Frontend (optional demo)

### Purpose
The demo frontend provides an interactive local walkthrough of the "lost-device" access control story through the real adapter using synthetic data. It demonstrates immediate revocation enforcement, tamper-evident audit logging, and independent access for unrevoked users.

### How to Run
1. Start the local server:
   ```bash
   python frontend/server.py
   ```
2. Open your browser and navigate to:
   ```
   http://127.0.0.1:8000
   ```

### Button Actions
- **Setup**: Initializes adapter state with two synthetic owners (`user-alex`, `user-blair`), two synthetic assets (`report-1`, `report-2`), and runtime key material generated with `secrets.token_hex(16)`. Returns `OK`.
- **Owner reads (allow)**: `user-alex` requests `report-1`. Since `user-alex` is an active owner, the adapter permits reading the asset body. Returns `ALLOW`.
- **Revoke owner**: Revokes `user-alex` to simulate a lost or compromised credential. Returns `OK`.
- **Owner reads again (deny)**: `user-alex` requests `report-1` again. Revocation is immediately enforced by the adapter. Returns `DENY`.
- **Audit**: Queries the adapter's tamper-evident audit log for the correlation ID of the revoked read attempt, proving that the denial was recorded in the signed hash-chained log. Returns `DENY`.
- **Second owner reads (allow)**: `user-blair` requests `report-2`. Confirms that revoking `user-alex` does not disrupt access for other legitimate users. Returns `ALLOW`.
- **Run messaging demo**: Runs `messaging.demo_part_a` in an isolated subprocess to verify post-quantum hybrid key exchange, authenticated transport, replay rejection, and chunk reassembly.
- **Reset**: Clears all displayed cards client-side without altering server state.

### Notes and Constraints
- **Standard Library Only**: The server is built entirely with Python 3.12 standard library modules (`http.server`, `subprocess`, `json`, `secrets`, `tempfile`, `sys`, `os`, `pathlib`). No external packages, pip dependencies, or CDN resources are used. The frontend runs completely offline.
- **Not Part of the Judged Adapter Path**: The demo frontend is strictly an optional visualization interface. The judged evaluation path (`track4_service.py`) remains completely independent and does not import or depend on anything in `frontend/`.
- **Localhost Only**: Binds strictly to `127.0.0.1:8000`.
- **Ephemeral State**: Creates a temporary state directory with `tempfile.mkdtemp()` at server start and deletes it on exit; it never writes inside the repository folder.

