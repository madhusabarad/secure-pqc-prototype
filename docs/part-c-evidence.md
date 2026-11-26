# Track 4: Trust, But Verify — Part C Evidence Sheet

**Scope:** Adapter skeleton, on-disk state store, tamper-evident audit log, crash recovery, backup integrity, and threat model.  
**Runtime:** Python 3.12, offline standard library + `pqcrypto==0.4.0`.  
**Date:** November 2026 | **Track:** Track 4 (Trust, but verify)

---

## Goal Summary Table

| Goal | Description & Scope | Expected Result | Status | Actual Result & Evidence Link |
| :--- | :--- | :--- | :--- | :--- |
| **Goal 3: Crash Recovery** | Single-commit write-ahead journal (`journal.json` -> atomic `os.replace` of `state.json`). Automatic crash detection on startup across 4 fault boundaries. | Revocations survive uncommitted crashes (roll-forward). State consistent. Audit events recorded exactly once. | **measured** | [Crash Recovery Measurement](#measurement-record-goal-3-crash-recovery) — 4/4 fault injection tests passed. |
| **Goal 4: Backup Integrity** | ML-DSA-65 signed backup manifests with SHA-256 digest verification, rollback rejection (`key_version`), and non-rollback union rule for revocations. | Damaged backups rejected without state modification. Old backups cannot restore revoked actors. | **measured** | [Backup Integrity Measurement](#measurement-record-goal-4-backup-integrity) — Tested via pytest: damaged backup refused, revocation preserved. |
| **Goal 5: Log Integrity** | Append-only canonical JSON Lines log (`audit.log`) with SHA-256 hash chaining and ML-DSA-65 signed checkpoint (`checkpoint.json`). | Mid-log modification detected via hash chain. Tail deletion detected via checkpoint seq/head mismatch and signature. | **measured** | [Log Integrity Measurement](#measurement-record-goal-5-log-integrity) — Verified via `scripts/verify_log.py` and pytest tamper tests. |

---

## Measurement Record: Goal 3 (Crash Recovery)

- **Claim:**  
  A simulated hard process crash (`os._exit(42)`) at any of the 4 transaction stages (`after_intent`, `after_commit`, `before_audit`, `after_audit`) preserves on-disk state consistency, guarantees that revoked actors remain denied, unaffected peers maintain access, and audit events are recorded idempotently (exactly once).
- **Setup and Input:**  
  - Script: [scripts/crash_test.py](file:///d:/secure-pqc-prototype/scripts/crash_test.py)  
  - Controlled hook: environment variable `TRACK4_CRASH_AT`  
  - Workload: Actor `alice` assigned asset `doc1`, peer `bob` assigned `doc2`. Revocation issued for `alice`.
- **Procedure:**  
  1. Initialize fresh temporary directory under `TRACK4_STATE_DIR`.
  2. Execute setup request in child process: `python -B track4_service.py`.
  3. Verify `alice` reads `doc1` with decision `allow`.
  4. Inject crash during `revoke` at step `after_intent` (`os._exit(42)`).
  5. Restart adapter and issue read request for `alice`. Verify recovery re-applies revocation and returns `deny`.
  6. Repeat steps 1–5 for `after_commit`, `before_audit`, and `after_audit`.
  7. Run complete harness via terminal:
     ```powershell
     python scripts/crash_test.py
     ```
- **Expected:**  
  All 4 crashed executions exit with code 42. Upon restart, `alice` is denied without body disclosure, `bob` retains `allow`, and the audit log contains exactly 1 `revoke` event per scenario.
- **Observed:**  
  ```text
  Starting Part C crash-recovery test suite across all 4 transaction boundaries...

  --- Testing crash injection at: after_intent ---
  Crashed process returned exit code: 42 (expected 42)
  PASS: Revocation persisted and actor is denied access.
  PASS: Unaffected peer retains authorized access.
  PASS: Revoke audit event recorded exactly once (correlation_id=rev-after_intent).
  PASS: Audit query completed.

  --- Testing crash injection at: after_commit ---
  Crashed process returned exit code: 42 (expected 42)
  PASS: Revocation persisted and actor is denied access.
  PASS: Unaffected peer retains authorized access.
  PASS: Revoke audit event recorded exactly once (correlation_id=rev-after_commit).
  PASS: Audit query completed.

  --- Testing crash injection at: before_audit ---
  Crashed process returned exit code: 42 (expected 42)
  PASS: Revocation persisted and actor is denied access.
  PASS: Unaffected peer retains authorized access.
  PASS: Revoke audit event recorded exactly once (correlation_id=rev-before_audit).
  PASS: Audit query completed.

  --- Testing crash injection at: after_audit ---
  Crashed process returned exit code: 42 (expected 42)
  PASS: Revocation persisted and actor is denied access.
  PASS: Unaffected peer retains authorized access.
  PASS: Revoke audit event recorded exactly once (correlation_id=rev-after_audit).
  PASS: Audit query completed.

  ALL 4 CRASH RECOVERY TESTS PASSED!
  ```
- **Evidence Path:**  
  - Implementation: [app/recovery.py](file:///d:/secure-pqc-prototype/app/recovery.py)
  - Test runner: [scripts/crash_test.py](file:///d:/secure-pqc-prototype/scripts/crash_test.py)
- **Limits:**  
  Tested against abrupt process termination (`os._exit`) simulating power failure or unhandled kills. Does not simulate disk-block hardware degradation or underlying OS filesystem corruption.

---

## Measurement Record: Goal 4 (Backup Integrity)

- **Claim:**  
  State backups are packaged with an ML-DSA-65 signed manifest containing a SHA-256 digest of canonical state contents and a monotonic `key_version`. Restoring any backup requires signature and digest verification prior to disk mutation. A restore cannot rollback `key_version` and cannot un-revoke any previously revoked actor (enforced by `current.revoked UNION backup.revoked`).
- **Setup and Input:**  
  - Module: [app/backup.py](file:///d:/secure-pqc-prototype/app/backup.py)
  - Test case: `tests/test_adapter.py::test_damaged_backup_is_refused` and `test_old_valid_backup_cannot_restore_revoked_actor`.
  - Workload: Setup state with `alice` and `bob`. Create backup. Revoke `alice`. Restore old valid backup.
- **Procedure:**  
  1. Create signed backup via `backup.create_backup(backup_path)`.
  2. Mutate backup state payload (simulate tampering) -> execute `backup.restore_backup()`. Assert `BackupError` is raised and state on disk is untouched.
  3. Tamper with ML-DSA-65 signature bytes -> execute restore. Assert `BackupError` raised and state untouched.
  4. Create valid backup before revoking `alice`.
  5. Issue `revoke` for `alice`. Verify `alice` is denied.
  6. Execute restore using pre-revocation backup.
  7. Run pytest suite:
     ```powershell
     pytest -v tests/test_adapter.py -k "backup"
     ```
- **Expected:**  
  Tampered backup rejected without modifying current state. Restoring from pre-revocation backup keeps `alice` revoked and preserves `bob` access.
- **Observed:**  
  ```text
  tests/test_adapter.py::test_damaged_backup_is_refused PASSED             [ 50%]
  tests/test_adapter.py::test_old_valid_backup_cannot_restore_revoked_actor PASSED [100%]
  ============================== 2 passed in 1.48s ==============================
  ```
- **Evidence Path:**  
  - Module: [app/backup.py](file:///d:/secure-pqc-prototype/app/backup.py)
  - Tests: [tests/test_adapter.py](file:///d:/secure-pqc-prototype/tests/test_adapter.py#L274-L335)
- **Limits:**  
  Backup verification relies on ML-DSA-65 public key in the backup bundle; if an attacker replaces both public key and signature, validation passes unless anchored against an out-of-band known key.

---

## Measurement Record: Goal 5 (Log Integrity)

- **Claim:**  
  Audit events written to `audit.log` are tamper-evident: modifying an existing log line breaks SHA-256 hash linkage, deleting lines from the tail causes sequence or head mismatch against ML-DSA-65 signed `checkpoint.json`, and embedding newlines or fake JSON in free-text fields does not corrupt log structure. Verification CLI exits 0 only when valid.
- **Setup and Input:**  
  - CLI: [scripts/verify_log.py](file:///d:/secure-pqc-prototype/scripts/verify_log.py)
  - Module: [app/audit.py](file:///d:/secure-pqc-prototype/app/audit.py)
  - Tests: `test_tampered_log_line_detected`, `test_deleting_last_entry_detected_via_checkpoint`, `test_newline_and_fake_json_injection_in_freetext`, `test_corrupted_checkpoint_detected`.
- **Procedure:**  
  1. Setup state and record 2 read events.
  2. Verify clean log passes via `scripts/verify_log.py`.
  3. Edit line 2 in `audit.log` (tamper actor). Run verification and verify detection.
  4. Delete line 3 in `audit.log` while keeping `checkpoint.json`. Run verification and verify tail truncation detection.
  5. Inject multi-line fake JSON in `request_id`. Verify log retains exact line count and valid cryptographic hashes.
  6. Corrupt signature in `checkpoint.json`. Verify signature check fails.
  7. Execute pytest suite:
     ```powershell
     pytest -v tests/test_adapter.py -k "log or checkpoint or injection"
     ```
- **Expected:**  
  All tamper attempts detected with specific failure reasons. Valid logs pass with exit code 0.
- **Observed:**  
  ```text
  tests/test_adapter.py::test_tampered_log_line_detected PASSED            [ 25%]
  tests/test_adapter.py::test_deleting_last_entry_detected_via_checkpoint PASSED [ 50%]
  tests/test_adapter.py::test_newline_and_fake_json_injection_in_freetext PASSED [ 75%]
  tests/test_adapter.py::test_corrupted_checkpoint_detected PASSED         [100%]
  ============================== 4 passed in 2.12s ==============================
  ```
  CLI run on clean log:
  ```text
  Verifying audit log in: C:\Users\Hp\AppData\Local\Temp\tmpnico3tox
  VERIFICATION SUCCESSFUL: 2 entries verified.
  Current Log Head: dd9fac92f27a640b3c12c5b7e902113fc8db91b8a0e46464175bc8b08ee86bf5
  Exit Code: 0
  ```
- **Evidence Path:**  
  - Implementation: [app/audit.py](file:///d:/secure-pqc-prototype/app/audit.py)
  - CLI: [scripts/verify_log.py](file:///d:/secure-pqc-prototype/scripts/verify_log.py)
  - Tests: [tests/test_adapter.py](file:///d:/secure-pqc-prototype/tests/test_adapter.py#L143-L230)
- **Limits:**  
  Verification confirms internal consistency and checkpoint signature. An adversary with write access to `TRACK4_STATE_DIR` could generate a new keypair and re-sign a forged log; detection requires comparing the head hash against an external anchor.

---

## Empirical Performance Benchmarks

Run via `python scripts/measure.py` (200 fresh subprocess invocations per operation, matching official judge runtime):

| Operation | Count | p50 Latency (ms) | p95 Latency (ms) |
| :--- | :--- | :--- | :--- |
| `setup` | 200 | 176.80 | 240.09 |
| `read` (allowed) | 200 | 191.12 | 251.46 |
| `read` (denied) | 200 | 193.30 | 257.60 |
| `audit` (lookup) | 200 | 147.96 | 165.15 |
| `revoke` (journal + commit) | 200 | 229.34 | 285.13 |

**Audit Log Storage Metrics (after 601 events):**
- `audit.log` file size: 334,996 bytes (327.14 KiB)
- `checkpoint.json` size: 10,638 bytes (10.39 KiB)
- Average entry size: 557.4 bytes per event
