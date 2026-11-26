"""Comprehensive test suite for Part C Track 4 requirements.

Covers:
- All 11 organizer validator checks
- Tampered audit log line detection
- Deleted log tail entry detection via ML-DSA-65 checkpoint
- Newline and JSON injection resistance in free-text fields
- Immunity to parameter spoofing (extra actor_id cannot change actor)
- Robust handling of malformed JSON, non-dict, oversized input, unknown op, and wrong types
- Truncated or corrupted checkpoint detection
- Refusal of damaged backup with state preservation
- Invariant enforcement: old backups cannot un-revoke an actor
"""

import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import pytest

from pqcrypto.kem.ml_kem_768 import decrypt as ml_kem_decrypt, generate_keypair as ml_kem_generate_keypair

REPO_ROOT = Path(__file__).parent.parent.resolve()
ENTRY_SCRIPT = REPO_ROOT / "track4_service.py"

from app import audit, backup, store


def execute_adapter(request_data, state_dir: Path, timeout: float = 10.0) -> tuple[int, str, str]:
    """Execute the adapter with the given raw input or dict in a fresh process."""
    env = os.environ.copy()
    env["TRACK4_STATE_DIR"] = str(state_dir)
    env["TMPDIR"] = str(state_dir)
    env["TEMP"] = str(state_dir)
    env["TMP"] = str(state_dir)

    cmd = [sys.executable, "-B", str(ENTRY_SCRIPT)]
    p = subprocess.Popen(
        cmd,
        cwd=REPO_ROOT,
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if isinstance(request_data, dict):
        raw_in = json.dumps(request_data).encode("utf-8")
    elif isinstance(request_data, str):
        raw_in = request_data.encode("utf-8")
    else:
        raw_in = request_data

    stdout, stderr = p.communicate(input=raw_in, timeout=timeout)
    return p.returncode, stdout.decode("utf-8"), stderr.decode("utf-8")


def call_op(state_dir: Path, **request) -> dict:
    """Helper to call adapter and return parsed JSON stdout."""
    rc, stdout, stderr = execute_adapter(request, state_dir)
    assert rc == 0, f"Adapter exited with code {rc}. stderr: {stderr}"
    assert stdout.strip(), "Adapter returned empty stdout"
    return json.loads(stdout)


# ==============================================================================
# SECTION 1: 11 VALIDATOR BEHAVIORS
# ==============================================================================

def test_validator_11_behaviors():
    """Verify all 11 core behaviors tested by the organizer validate.py script."""
    with tempfile.TemporaryDirectory(prefix="t4-val11-") as temp_dir:
        state_dir = Path(temp_dir)
        actor, peer, disabled = [secrets.token_hex(16) for _ in range(3)]
        asset, other = [secrets.token_hex(12) for _ in range(2)]
        body, peer_body, marker = [secrets.token_hex(24) for _ in range(3)]

        # 1. Setup
        initial = {
            "op": "setup",
            "owners": {asset: actor, other: peer},
            "contents": {asset: body, other: peer_body},
            "disabled": [disabled],
            "key_material": marker,
        }
        res_setup = call_op(state_dir, **initial)
        assert res_setup.get("ready") is True

        # 2. Owner allow with exact body
        req_id1 = secrets.token_hex(16)
        res_read1 = call_op(state_dir, op="read", actor=actor, asset=asset, request_id=req_id1)
        assert res_read1.get("decision") == "allow"
        assert res_read1.get("body") == body

        # 3. Peer allow with exact body
        req_id2 = secrets.token_hex(16)
        res_read2 = call_op(state_dir, op="read", actor=peer, asset=other, request_id=req_id2)
        assert res_read2.get("decision") == "allow"
        assert res_read2.get("body") == peer_body

        # 4. Wrong owner deny (actor trying to read peer asset)
        req_id3 = secrets.token_hex(16)
        res_read3 = call_op(state_dir, op="read", actor=actor, asset=other, request_id=req_id3)
        assert res_read3.get("decision") == "deny"
        assert "body" not in res_read3 or not res_read3["body"]

        # 5. Revoke actor
        res_revoke = call_op(state_dir, op="revoke", actor=actor)
        assert isinstance(res_revoke, dict)

        # 6. Revoked owner deny with no body
        req_id4 = secrets.token_hex(16)
        res_read4 = call_op(state_dir, op="read", actor=actor, asset=asset, request_id=req_id4)
        assert res_read4.get("decision") == "deny"
        assert "body" not in res_read4 or not res_read4["body"]

        # 7. Audit returns request_id + deny
        res_audit = call_op(state_dir, op="audit", request_id=req_id4)
        assert res_audit.get("request_id") == req_id4
        assert res_audit.get("decision") == "deny"

        # 8. Unaffected peer allow
        req_id5 = secrets.token_hex(16)
        res_read5 = call_op(state_dir, op="read", actor=peer, asset=other, request_id=req_id5)
        assert res_read5.get("decision") == "allow"
        assert res_read5.get("body") == peer_body

        # 9. Revocation persists across processes
        req_id6 = secrets.token_hex(16)
        res_read6 = call_op(state_dir, op="read", actor=actor, asset=asset, request_id=req_id6)
        assert res_read6.get("decision") == "deny"
        assert "body" not in res_read6 or not res_read6["body"]

        # 10. Fresh rerun setup in brand-new directory
        with tempfile.TemporaryDirectory(prefix="t4-fresh-") as fresh_dir:
            f_dir = Path(fresh_dir)
            res_fresh = call_op(f_dir, **initial)
            assert res_fresh.get("ready") is True
            res_fresh_read = call_op(f_dir, op="read", actor=actor, asset=asset, request_id=secrets.token_hex(16))
            assert res_fresh_read.get("decision") == "allow"
            assert res_fresh_read.get("body") == body

        # 11. key_material never in stdout/stderr
        rc, out, err = execute_adapter(initial, state_dir)
        assert marker not in out
        assert marker not in err


# ==============================================================================
# SECTION 2: AUDIT LOG INTEGRITY & TAMPER DETECTION
# ==============================================================================

def test_tampered_log_line_detected():
    """Editing an existing log line invalidates the hash chain and is detected."""
    with tempfile.TemporaryDirectory() as temp_dir:
        s_dir = Path(temp_dir)
        call_op(s_dir, op="setup", owners={"d1": "alice"}, contents={"d1": "secret"}, disabled=[], key_material="seed")
        call_op(s_dir, op="read", actor="alice", asset="d1", request_id="r1")
        call_op(s_dir, op="read", actor="bob", asset="d1", request_id="r2")

        # Initial log is valid
        report = audit.verify_audit_log(s_dir)
        assert report["valid"] is True
        assert report["entries_count"] == 3

        # Tamper with the second line in audit.log (change action or actor)
        log_path = s_dir / "audit.log"
        lines = log_path.read_text(encoding="utf-8").splitlines()
        entry1 = json.loads(lines[1])
        entry1["actor"] = "mallory_tamper"
        lines[1] = json.dumps(entry1)
        log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        # Verify must fail and flag bad line
        tampered_report = audit.verify_audit_log(s_dir)
        assert tampered_report["valid"] is False
        assert tampered_report["bad_line"] == 2
        assert "Hash mismatch" in tampered_report["reason"]


def test_deleting_last_entry_detected_via_checkpoint():
    """Deleting tail log entries is detected because checkpoint seq/head mismatch."""
    with tempfile.TemporaryDirectory() as temp_dir:
        s_dir = Path(temp_dir)
        call_op(s_dir, op="setup", owners={"d1": "alice"}, contents={"d1": "secret"}, disabled=[], key_material="seed")
        call_op(s_dir, op="read", actor="alice", asset="d1", request_id="r1")
        call_op(s_dir, op="read", actor="alice", asset="d1", request_id="r2")

        report_init = audit.verify_audit_log(s_dir)
        assert report_init["valid"] is True
        assert report_init["entries_count"] == 3

        # Delete the last entry (line 3) from audit.log without touching checkpoint.json
        log_path = s_dir / "audit.log"
        lines = log_path.read_text(encoding="utf-8").splitlines()
        log_path.write_text("\n".join(lines[:2]) + "\n", encoding="utf-8")

        # Verify must detect truncation
        trunc_report = audit.verify_audit_log(s_dir)
        assert trunc_report["valid"] is False
        assert "Tail truncation detected" in trunc_report["reason"]


def test_newline_and_fake_json_injection_in_freetext():
    """Newlines and fake JSON in request fields remain safely escaped in a single line."""
    with tempfile.TemporaryDirectory() as temp_dir:
        s_dir = Path(temp_dir)
        call_op(s_dir, op="setup", owners={"d1": "alice"}, contents={"d1": "secret"}, disabled=[], key_material="seed")

        # Malicious payload with embedded newlines and fake JSON entry
        fake_payload = "evil_id\n{\"seq\":99,\"actor\":\"attacker\",\"action\":\"inject\",\"hash\":\"fake\"}\n"
        call_op(s_dir, op="read", actor="alice", asset="d1", request_id=fake_payload)

        # Log must have exactly 2 lines, and remain 100% cryptographically valid
        log_path = s_dir / "audit.log"
        raw_content = log_path.read_text(encoding="utf-8")
        lines = [ln for ln in raw_content.splitlines() if ln.strip()]
        assert len(lines) == 2, f"Expected 2 lines, got {len(lines)}"

        report = audit.verify_audit_log(s_dir)
        assert report["valid"] is True, f"Log corrupted by injection: {report}"
        assert report["entries_count"] == 2


def test_extra_actor_id_cannot_change_recorded_actor():
    """An extra 'actor_id' field in request dictionary is ignored; actor is strictly request['actor']."""
    with tempfile.TemporaryDirectory() as temp_dir:
        s_dir = Path(temp_dir)
        call_op(s_dir, op="setup", owners={"d1": "alice"}, contents={"d1": "secret"}, disabled=[], key_material="seed")

        # Send request with conflicting actor and actor_id
        req = {
            "op": "read",
            "actor": "bob",
            "actor_id": "alice",
            "asset": "d1",
            "request_id": "req-spoof-attempt",
        }
        res = call_op(s_dir, **req)
        assert res.get("decision") == "deny"

        # Check recorded actor in audit event
        event = audit.find_event_by_correlation_id("req-spoof-attempt", state_dir=s_dir)
        assert event is not None
        assert event["actor"] == "bob", f"Spoofed actor recorded: {event['actor']}"


# ==============================================================================
# SECTION 3: ROBUST INPUT VALIDATION & NO LEAKS
# ==============================================================================

@pytest.mark.parametrize("bad_input", [
    b"not a json object",
    b"",
    b'{"op": "read", broken json',
    b"[1, 2, 3]",
    b'"just a string"',
    b'{"op": "nonexistent_op"}',
    b'{"op": 12345}',
    b'{"op": "read", "actor": 999, "asset": "d1"}',
    b'{"op": "read", "actor": "alice", "asset": {"nested": "dict"}}',
])
def test_malformed_and_invalid_inputs_generic_error(bad_input):
    """Malformed or schema-violating inputs exit with code 1 and generic error message."""
    with tempfile.TemporaryDirectory() as temp_dir:
        s_dir = Path(temp_dir)
        rc, stdout, stderr = execute_adapter(bad_input, s_dir)
        assert rc == 1, f"Expected exit code 1 for invalid input {bad_input}, got {rc}"
        assert "Request failed; inspect team application locally." in stderr
        # Must disclose zero output on stdout
        assert stdout == ""


def test_oversized_input_rejected():
    """Requests exceeding 1 MiB are rejected with generic error."""
    with tempfile.TemporaryDirectory() as temp_dir:
        s_dir = Path(temp_dir)
        huge_payload = json.dumps({"op": "setup", "huge": "A" * (1048576 + 10)}).encode("utf-8")
        rc, stdout, stderr = execute_adapter(huge_payload, s_dir)
        assert rc == 1
        assert "Request failed; inspect team application locally." in stderr


def test_corrupted_checkpoint_detected():
    """Corrupted checkpoint data or invalid signature is flagged by verify."""
    with tempfile.TemporaryDirectory() as temp_dir:
        s_dir = Path(temp_dir)
        call_op(s_dir, op="setup", owners={"d1": "alice"}, contents={"d1": "secret"}, disabled=[], key_material="seed")

        cp_path = s_dir / "checkpoint.json"
        cp_data = json.loads(cp_path.read_text(encoding="utf-8"))

        # Corrupt signature
        cp_data["sig"] = "00" * 3309
        cp_path.write_text(json.dumps(cp_data), encoding="utf-8")

        report = audit.verify_audit_log(s_dir)
        assert report["valid"] is False
        assert "signature verification failed" in report["reason"]


# ==============================================================================
# SECTION 4: BACKUP INTEGRITY & REVOCATION PRESERVATION
# ==============================================================================

def test_damaged_backup_is_refused():
    """Damaged backup (tampered signature or altered content) is rejected leaving state intact."""
    with tempfile.TemporaryDirectory() as temp_dir:
        s_dir = Path(temp_dir)
        os.environ["TRACK4_STATE_DIR"] = str(s_dir)

        call_op(s_dir, op="setup", owners={"d1": "alice"}, contents={"d1": "secret"}, disabled=[], key_material="seed")
        state_before = store.load_state()

        backup_file = s_dir / "test_backup.json"
        backup.create_backup(backup_file)

        # 1. Tamper with content
        raw = json.loads(backup_file.read_text(encoding="utf-8"))
        raw["content"]["state"]["contents"]["d1"] = "tampered secret"
        tampered_file = s_dir / "tampered_backup.json"
        tampered_file.write_text(json.dumps(raw), encoding="utf-8")

        with pytest.raises(backup.BackupError, match="hash verification failed"):
            backup.restore_backup(tampered_file)

        # State must remain untouched
        assert store.load_state() == state_before

        # 2. Tamper with signature
        raw["signature"] = "00" * 3309
        bad_sig_file = s_dir / "badsig_backup.json"
        bad_sig_file.write_text(json.dumps(raw), encoding="utf-8")

        with pytest.raises(backup.BackupError, match="signature verification failed"):
            backup.restore_backup(bad_sig_file)

        # State must remain untouched
        assert store.load_state() == state_before


def test_old_valid_backup_cannot_restore_revoked_actor():
    """An old backup cannot un-revoke an actor; revoked state persists across restores."""
    with tempfile.TemporaryDirectory() as temp_dir:
        s_dir = Path(temp_dir)
        os.environ["TRACK4_STATE_DIR"] = str(s_dir)

        call_op(s_dir, op="setup", owners={"d1": "alice", "d2": "bob"}, contents={"d1": "a_data", "d2": "b_data"}, disabled=[], key_material="seed")

        # Create valid backup while alice is NOT revoked
        backup_file = s_dir / "alice_active.json"
        backup.create_backup(backup_file)

        # Now revoke alice
        call_op(s_dir, op="revoke", actor="alice")
        res_denied = call_op(s_dir, op="read", actor="alice", asset="d1", request_id="r_denied")
        assert res_denied.get("decision") == "deny"

        # Restore from the older backup
        backup.restore_backup(backup_file)

        # Invariant check: alice MUST STILL BE REVOKED!
        res_post_restore = call_op(s_dir, op="read", actor="alice", asset="d1", request_id="r_post_restore")
        assert res_post_restore.get("decision") == "deny", "Alice was un-revoked by older backup restore!"
        assert "body" not in res_post_restore

        # Unaffected peer bob still retains access
        res_bob = call_op(s_dir, op="read", actor="bob", asset="d2", request_id="r_bob")
        assert res_bob.get("decision") == "allow"
        assert res_bob.get("body") == "b_data"


def test_adapter_protected_read_end_to_end():
    """End-to-end test of protected_read via adapter subprocess with real ML-KEM-768."""
    with tempfile.TemporaryDirectory() as temp_dir:
        s_dir = Path(temp_dir)
        os.environ["TRACK4_STATE_DIR"] = str(s_dir)

        # 1. Setup
        body = "Top-secret PQC payload content 42"
        setup_resp = call_op(
            s_dir,
            op="setup",
            owners={"asset_secret": "alice", "asset_bob": "bob"},
            contents={"asset_secret": body, "asset_bob": "bob data"},
            disabled=[],
            key_material="kem_test_seed",
        )
        assert setup_resp.get("ready") is True

        # Generate real ML-KEM-768 keypair
        pk, sk = ml_kem_generate_keypair()
        pk_b64 = base64.b64encode(pk).decode("ascii")
        challenge = "random-challenge-xyz-98765"

        # 2. Protected read for allowed owner
        resp = call_op(
            s_dir,
            op="protected_read",
            actor="alice",
            asset="asset_secret",
            challenge=challenge,
            public_key=pk_b64,
            request_id="req_prot_01",
        )
        assert "ciphertext" in resp
        assert "proof" in resp
        assert resp.get("decision") != "deny"

        # Decrypt ciphertext with ML-KEM secret key and recompute HMAC
        ct_bytes = base64.b64decode(resp["ciphertext"], validate=True)
        shared_secret = ml_kem_decrypt(sk, ct_bytes)
        expected_msg = (challenge + body).encode("utf-8")
        expected_proof = hmac.new(shared_secret, expected_msg, hashlib.sha256).hexdigest()
        assert resp["proof"] == expected_proof

        # Verify audit event for protected_read
        audit_resp = call_op(s_dir, op="audit", request_id="req_prot_01")
        assert audit_resp.get("decision") == "allow"

        # 3. Revoked owner -> must return {"decision": "deny"} without ciphertext
        call_op(s_dir, op="revoke", actor="alice", request_id="req_rev_alice")
        resp_revoked = call_op(
            s_dir,
            op="protected_read",
            actor="alice",
            asset="asset_secret",
            challenge="fresh-challenge-after-revoke",
            public_key=pk_b64,
            request_id="req_prot_02",
        )
        assert resp_revoked == {"decision": "deny"}
        assert "ciphertext" not in resp_revoked

        # 4. Garbage key -> must return {"decision": "deny"} without ciphertext
        resp_garbage = call_op(
            s_dir,
            op="protected_read",
            actor="bob",
            asset="asset_bob",
            challenge="challenge-garbage-key",
            public_key="not-a-valid-base64-or-key",
            request_id="req_prot_03",
        )
        assert resp_garbage == {"decision": "deny"}
        assert "ciphertext" not in resp_garbage

