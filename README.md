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

## Frontend (Full Security Console & Demo)

### Purpose
The demo frontend provides a unified, interactive local Security Operations Center (SOC) console demonstrating the complete Track 4 workflow:
1. **Lost-Device Access Control & Key Lifecycle**: Setup, immediate revocation enforcement, audit logging, unaffected peer isolation, lost-device re-enrollment, and transactional key rotation.
2. **SOC Anomaly Detection & Incident Feed**: Ingests distributed synthetic access logs with clock-skew correction and order uncertainty flagging, displays real-time explainable alerts (unapproved privilege escalations, lateral movement hops, data access spikes), and reports benchmark metrics ($F_1 = 1.0$, $0.0$ false alerts/1k, $18.0\,\text{s}$ MTTA).
3. **PQC Secure Messaging**: Interactive execution of hybrid ML-KEM-768 + X25519 key exchange, ML-DSA-65 signatures, AES-256-GCM transport, replay rejection, and chunk reassembly.
4. **Tamper-Evident Audit Log & Cryptographic Verification**: Live inspection of canonical JSON Lines SHA-256 hash chains, ML-DSA-65 signed checkpoints, one-click cryptographic verification (`app.audit.verify_audit_log`), and interactive tamper-detection simulation.

### How to Run
1. Start the local server:
   ```bash
   python frontend/server.py
   ```
2. Open your browser and navigate to:
   ```
   http://127.0.0.1:8000
   ```

### Tabs & Capabilities
- **Tab 1: 🔐 Access & Lost-Device**:
  - `1. Setup`: Initializes synthetic owners (`user-alex`, `user-blair`) and assets.
  - `2. Owner Reads`: `user-alex` requests `report-1` $\to$ `ALLOW`.
  - `3. Revoke Owner`: Simulates lost or stolen device $\to$ `OK`.
  - `4. Owner Reads Again`: Immediate revocation enforcement $\to$ `DENY`.
  - `5. Audit`: Verifies denial recorded in signed hash-chained audit log $\to$ `DENY`.
  - `6. Peer Reads`: Confirms `user-blair` retains access $\to$ `ALLOW`.
  - `7. Re-enrol Lost Device`: Registers fresh quantum device key for `user-alex` $\to$ `OK`.
  - `8. Post-Reenrol Read`: Restores authorized access for `user-alex` $\to$ `ALLOW`.
  - `9. Rotate Key Material`: Atomic key rotation with version cutoff $\to$ `key_version: 2`.
- **Tab 2: 🚨 Anomaly Detector & SOC Feed**:
  - Live benchmark HUD: $F_1 = 1.0$, Precision: $1.0$, Recall: $1.0$, False Alerts: $0.0 / 1,000$, MTTA: $18.0\,\text{s}$.
  - `Ingest Access Logs`: Renders synthetic distributed logs with clock offsets and uncertainty tags.
  - `Run Anomaly Detector`: Evaluates events and surfaces explainable alerts.
  - `Inject Unapproved Escalation`: Simulates unauthorized `superadmin` role change without ticket.
  - `Inject Lateral Movement Hop`: Simulates unauthorized `portal` $\to$ `database_admin` transition.
- **Tab 3: 💬 PQC Secure Messaging**:
  - Spawns `messaging.demo_part_a` in an isolated sandbox subprocess and displays live test output.
- **Tab 4: 📜 Audit Log & Cryptographic Proof**:
  - Displays canonical SHA-256 chained log entries and ML-DSA-65 checkpoint signatures.
  - `Run Cryptographic Verification`: Validates hash chain and signature across all entries.
  - `Simulate Tampering & Detect`: Proves that modifying a single byte in the log is immediately detected.

### Notes and Constraints
- **Standard Library Only**: Runs completely offline using Python 3.12 standard library modules (`http.server`, `subprocess`, `json`, `secrets`, `tempfile`, `sys`, `os`, `pathlib`). No external frontend frameworks or CDN assets required.
- **Isolated Judged Path**: Uses clean subprocess execution against `track4_service.py` with temporary state isolation (`TRACK4_STATE_DIR`), preserving adapter integrity.


## Credits

Adapter starters and the validator come from the official Track 4 Toolkit (`ScalerOpenSourceLabs/Track-4-Toolkit`).

