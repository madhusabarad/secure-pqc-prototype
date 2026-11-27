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

## Frontend (Real-Time Post-Quantum Security Platform)

### Purpose & Architecture
The frontend is a real-time, light-themed Security Operations Center (SOC) and Post-Quantum Security Platform that replaces static simulation scripts with a fully interactive, live web application:
1. **Live PQC Secure Messenger**: Interactive chat console between peers with live hybrid key exchange (X25519 + ML-KEM-768 authenticated via ML-DSA-65 signatures), AES-256-GCM directional transport, real-time packet inspection (AAD header, nonces, ciphertext), and active adversary attack simulators (live replay rejection, bit-flipping tamper rejection).
2. **Dynamic Vault & Access Control**: Create custom sensitive documents, assign dynamic ownership policies, test real-time access evaluation and ML-KEM-768 encapsulated protected reads, test immediate lost-device revocation enforcement (instant `DENY`), re-enroll quantum hardware keys, and perform atomic key rotation.
3. **Live SOC Threat Feed & Anomaly Center**: Real-time event ingestion pipeline with clock-skew compensation and order-uncertainty detection. Inject live adversary threats (unapproved privilege escalations, unauthorized lateral movement hops, bulk data exfiltration bursts) and receive explainable alert cards with MITRE ATT&CK technique IDs and benchmark metrics ($F_1 = 1.0$, $0.0$ false alerts/1k, $18.0\,\text{s}$ MTTA).
4. **Cryptographic Audit Ledger**: Real-time inspection of canonical JSON Lines SHA-256 hash chains and ML-DSA-65 signed checkpoints, with one-click mathematical verification (`app.audit.verify_audit_log`) and interactive tamper detection.

### Modern Light Theme
Built with an executive, modern light-theme design system (clean slate background `#f8fafc`, crisp white elevated cards, high-contrast typography `#0f172a`, and vibrant status badges) with no dark themes.

### How to Run
1. Start the local server:
   ```bash
   python frontend/server.py
   ```
2. Open your browser and navigate to:
   ```
   http://127.0.0.1:8000
   ```

### Real-Time Modules
- **💬 Live PQC Messenger**:
  - `Establish Hybrid Handshake`: Computes ephemeral X25519 and ML-KEM-768 secrets, signs transcript with ML-DSA-65, and derives session keys via HKDF-SHA256.
  - `Real-Time Chat Input`: Type and transmit arbitrary encrypted messages with monotonic counter nonces.
  - `Cryptographic Packet Inspector`: Real-time inspection of encrypted packets on the wire.
  - `Simulate Replay Attack`: Proves the replay filter immediately rejects duplicate packets (`STATUS_FAILED` $\to$ `REPLAY`).
  - `Simulate Bit-Flip Tampering`: Proves AES-256-GCM authentication tags catch transit mutations (`STATUS_FAILED` $\to$ `INTEGRITY`).
  - `Revoke Peer Identity`: Blocks peer credentials and terminates communication.
- **🔐 Dynamic Vault & Access Control**:
  - `Create Asset`: Dynamically register custom sensitive resources and owners.
  - `Request Read`: Real-time policy evaluation (`ALLOW` vs `DENY`).
  - `ML-KEM-768 Encapsulation`: Executes post-quantum protected read with HMAC verification.
  - `Revoke Device`: Instant device credential revocation resulting in real-time denial.
  - `Re-enroll Quantum Key`: Registers fresh device keys and restores authorized access.
  - `Rotate Keys`: Monotonically increments key versions and commits new key material.
- **🚨 Live SOC Threat Center**:
  - Continuous telemetry ingestion stream with clock-skew adjustment.
  - Threat triggers for MITRE ATT&CK techniques: Privilege Escalation (`T1078.004`), Lateral Movement (`T1021.002`), and Bulk Exfiltration (`T1048`).
- **📜 Cryptographic Audit Ledger**:
  - Visual blockchain-style ledger blocks showing Block #, Timestamp, Actor, Action, Previous Hash, and Block Hash.
  - `Cryptographically Verify Ledger`: Mathematically verifies full SHA-256 hash chains and ML-DSA-65 checkpoint signatures.
  - `Simulate Byte Tampering`: Live demonstration that mutating even 1 byte in the ledger immediately breaks verification at the exact corrupted block.

### Notes and Constraints
- **Standard Library Only**: Runs completely offline using Python 3.12 standard library modules (`http.server`, `subprocess`, `json`, `secrets`, `tempfile`, `sys`, `os`, `pathlib`). No external frontend frameworks or CDN assets required.
- **Isolated Judged Path**: Uses clean subprocess execution against `track4_service.py` with temporary state isolation (`TRACK4_STATE_DIR`), preserving adapter integrity.


## Credits

Adapter starters and the validator come from the official Track 4 Toolkit (`ScalerOpenSourceLabs/Track-4-Toolkit`).

