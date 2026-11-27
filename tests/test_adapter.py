"""Comprehensive test suite for Track 4 Part C: Security, Access, and Integrity.

Covers:
- All 11 organizer validator behaviors
- Specific attack tests named after attacks:
  - test_attack_input
  - test_attack_extra_fields
  - test_attack_path_traversal
  - test_attack_log_injection
  - test_attack_access
  - test_attack_persistence
  - test_attack_log_tamper
  - test_attack_backup
  - test_attack_concurrency
  - test_attack_leak_check
  - test_attack_messaging_end_to_end
"""

import base64
import concurrent.futures
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time
import pytest

from pqcrypto.kem.ml_kem_768 import (
    PUBLIC_KEY_SIZE as KEM_PK_SIZE,
    decrypt as ml_kem_decrypt,
    generate_keypair as ml_kem_generate_keypair,
)

REPO_ROOT = Path(__file__).parent.parent.resolve()
ENTRY_SCRIPT = REPO_ROOT / "track4_service.py"

from auditlog import audit, backup, store


def execute_adapter(request_data, state_dir: Path, timeout: float = 12.0) -> tuple[int, str, str]:
    """Execute the adapter with given input in a fresh subprocess."""
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
    """Helper to execute adapter request and return decoded JSON response."""
    rc, stdout, stderr = execute_adapter(request, state_dir)
    assert rc == 0, f"Adapter failed (rc={rc}). stderr: {stderr}"
    assert stdout.strip(), "Adapter returned empty stdout"
    return json.loads(stdout)


# ==============================================================================
# SECTION 1: VALIDATOR 11 BEHAVIORS
# ==============================================================================

def test_validator_11_behaviors():
    """Verify all 11 core behaviors required by official validator."""
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

        # 4. Wrong owner deny
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
# SECTION 2: ATTACK TESTS (ONE PER ATTACK, NAMED AFTER IT)
# ==============================================================================

def test_attack_input():
    """Attack: malformed JSON, non-dict, empty input, oversized input, wrong types, unknown op, missing op."""
    with tempfile.TemporaryDirectory(prefix="t4-atk-input-") as temp_dir:
        s_dir = Path(temp_dir)
        call_op(s_dir, op="setup", owners={"doc1": "alice"}, contents={"doc1": "topsecret"}, disabled=[], key_material="sec")

        # 1. Malformed JSON
        rc, out, err = execute_adapter(b"{malformed json...", s_dir)
        assert rc == 1
        assert "Request failed; inspect team application locally." in err
        assert out == ""

        # 2. Non-dict inputs
        for non_dict in [b"[1, 2, 3]", b'"just a string"', b"12345", b"true"]:
            rc, out, err = execute_adapter(non_dict, s_dir)
            assert rc == 1
            assert "Request failed; inspect team application locally." in err
            assert out == ""

        # 3. Empty input
        rc, out, err = execute_adapter(b"", s_dir)
        assert rc == 1
        assert "Request failed; inspect team application locally." in err
        assert out == ""

        # 4. Oversized input (e.g. huge string payload)
        huge = json.dumps({"op": "setup", "huge": "X" * (1048576 + 50)}).encode("utf-8")
        rc, out, err = execute_adapter(huge, s_dir)
        assert rc in (0, 1)  # If accepted or rejected, must not leak
        assert "X" * 100 not in out and "X" * 100 not in err

        # 5. Wrong types for every field -> fail-closed for access ops
        wrong_type_cases = [
            {"op": "read", "actor": 12345, "asset": "doc1", "request_id": "r1"},
            {"op": "read", "actor": "alice", "asset": ["not", "string"], "request_id": "r2"},
            {"op": "read", "actor": "alice", "asset": "doc1", "request_id": None},
            {"op": "protected_read", "actor": {"nested": "obj"}, "asset": "doc1", "challenge": "c", "public_key": "k"},
            {"op": "protected_read", "actor": "alice", "asset": "doc1", "challenge": 999, "public_key": "k"},
            {"op": "protected_read", "actor": "alice", "asset": "doc1", "challenge": "c", "public_key": False},
        ]
        for req in wrong_type_cases:
            res = call_op(s_dir, **req)
            assert res == {"decision": "deny"}, f"Expected fail-closed deny for {req}, got {res}"
            assert "body" not in res
            assert "ciphertext" not in res

        # Wrong type for audit -> returns request_id and deny
        audit_res = call_op(s_dir, op="audit", request_id=12345)
        assert audit_res.get("decision") == "deny"

        # 6. Unknown op & missing op -> generic exit 1
        rc, out, err = execute_adapter({"op": "unknown_hack_op"}, s_dir)
        assert rc == 1
        assert "Request failed; inspect team application locally." in err
        assert out == ""

        rc, out, err = execute_adapter({"actor": "alice"}, s_dir)
        assert rc == 1
        assert "Request failed; inspect team application locally." in err
        assert out == ""


def test_attack_extra_fields():
    """Attack: extra fields (e.g. actor_id=admin or role=admin) must not change recorded actor or decision."""
    with tempfile.TemporaryDirectory(prefix="t4-atk-extra-") as temp_dir:
        s_dir = Path(temp_dir)
        call_op(s_dir, op="setup", owners={"doc1": "alice"}, contents={"doc1": "classified"}, disabled=[], key_material="sec")

        # Attempt to impersonate alice or escalate via extra fields
        spoof_req = {
            "op": "read",
            "actor": "eve",
            "actor_id": "alice",
            "role": "admin",
            "asset": "doc1",
            "request_id": "req-spoof-1",
        }
        res = call_op(s_dir, **spoof_req)
        assert res.get("decision") == "deny"
        assert "body" not in res

        # Verify the recorded audit log event records actual actor "eve"
        event = audit.find_event_by_correlation_id("req-spoof-1", state_dir=s_dir)
        assert event is not None
        assert event["actor"] == "eve"
        assert event["outcome"] == "deny"


def test_attack_path_traversal():
    """Attack: directory traversal sequences, device names, and unicode in IDs must not touch files outside state dir."""
    with tempfile.TemporaryDirectory(prefix="t4-atk-traversal-") as temp_dir:
        s_dir = Path(temp_dir)

        traversal_assets = {
            "../../outside.txt": "actor1",
            "C:\\Windows\\System32\\calc.exe": "actor2",
            "a/b/c/nested": "actor3",
            "con": "actor4",
            "unicode_α_β_γ_🔒": "actor5",
        }
        traversal_contents = {
            "../../outside.txt": "content1",
            "C:\\Windows\\System32\\calc.exe": "content2",
            "a/b/c/nested": "content3",
            "con": "content4",
            "unicode_α_β_γ_🔒": "content5",
        }

        # Setup with traversal IDs
        res = call_op(s_dir, op="setup", owners=traversal_assets, contents=traversal_contents, disabled=[], key_material="sec")
        assert res.get("ready") is True

        # Ensure no file was created outside state directory
        outside_file = s_dir.parent / "outside.txt"
        assert not outside_file.exists(), "Path traversal created file outside state dir!"

        # Read allowed owner
        res_read = call_op(s_dir, op="read", actor="actor1", asset="../../outside.txt", request_id="r-trav-1")
        assert res_read.get("decision") == "allow"
        assert res_read.get("body") == "content1"

        # Read unicode asset
        res_uni = call_op(s_dir, op="read", actor="actor5", asset="unicode_α_β_γ_🔒", request_id="r-trav-2")
        assert res_uni.get("decision") == "allow"
        assert res_uni.get("body") == "content5"


def test_attack_log_injection():
    """Attack: newlines and fake JSON event in IDs stay within one entry and do not split log lines."""
    with tempfile.TemporaryDirectory(prefix="t4-atk-loginj-") as temp_dir:
        s_dir = Path(temp_dir)
        call_op(s_dir, op="setup", owners={"doc1": "alice"}, contents={"doc1": "data"}, disabled=[], key_material="sec")

        # Injected newline + fake event payload
        malicious_id = "req_legit\n{\"seq\":999,\"actor\":\"attacker\",\"action\":\"fake_grant\",\"hash\":\"0000\"}\n"
        call_op(s_dir, op="read", actor="alice", asset="doc1", request_id=malicious_id)

        # Log must have exactly 2 lines (setup + read)
        log_path = s_dir / "audit.log"
        lines = [ln for ln in log_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
        assert len(lines) == 2, f"Log was split by newline injection! Found {len(lines)} lines."

        # Cryptographic verification must pass
        report = audit.verify_audit_log(s_dir)
        assert report["valid"] is True, f"Log verification failed after injection attempt: {report}"
        assert report["entries_count"] == 2


def test_attack_access():
    """Attack: check all access boundaries (owner, non-owner, disabled, revoked, read vs protected_read)."""
    with tempfile.TemporaryDirectory(prefix="t4-atk-access-") as temp_dir:
        s_dir = Path(temp_dir)
        call_op(
            s_dir,
            op="setup",
            owners={"doc_alice": "alice", "doc_eve": "eve"},
            contents={"doc_alice": "alice_secret", "doc_eve": "eve_secret"},
            disabled=["eve"],
            key_material="sec",
        )

        # 1. Owner allow
        r1 = call_op(s_dir, op="read", actor="alice", asset="doc_alice", request_id="r1")
        assert r1 == {"decision": "allow", "body": "alice_secret"}

        # 2. Wrong owner deny
        r2 = call_op(s_dir, op="read", actor="bob", asset="doc_alice", request_id="r2")
        assert r2 == {"decision": "deny"}
        assert "body" not in r2

        # 3. Disabled deny
        r3 = call_op(s_dir, op="read", actor="eve", asset="doc_eve", request_id="r3")
        assert r3 == {"decision": "deny"}
        assert "body" not in r3

        # 4. Revoked deny
        call_op(s_dir, op="revoke", actor="alice", request_id="rev1")
        r4 = call_op(s_dir, op="read", actor="alice", asset="doc_alice", request_id="r4")
        assert r4 == {"decision": "deny"}
        assert "body" not in r4

        # 5. Read and protected_read give identical decisions
        pk, _ = ml_kem_generate_keypair()
        pk_b64 = base64.b64encode(pk).decode("ascii")

        pr_wrong = call_op(s_dir, op="protected_read", actor="bob", asset="doc_alice", challenge="c", public_key=pk_b64, request_id="pr1")
        assert pr_wrong == {"decision": "deny"}

        pr_disabled = call_op(s_dir, op="protected_read", actor="eve", asset="doc_eve", challenge="c", public_key=pk_b64, request_id="pr2")
        assert pr_disabled == {"decision": "deny"}

        pr_revoked = call_op(s_dir, op="protected_read", actor="alice", asset="doc_alice", challenge="c", public_key=pk_b64, request_id="pr3")
        assert pr_revoked == {"decision": "deny"}


def test_attack_persistence():
    """Attack: verify state persistence, repeated setup fresh state, read before setup, unknown revoke, duplicate request_ids."""
    with tempfile.TemporaryDirectory(prefix="t4-atk-persist-") as temp_dir:
        s_dir = Path(temp_dir)

        # 1. Read before setup -> generic failure / fail closed
        rc, out, err = execute_adapter({"op": "read", "actor": "alice", "asset": "d1", "request_id": "r0"}, s_dir)
        # Fail closed: either returns {"decision":"deny"} or exit 1
        if rc == 0:
            assert json.loads(out) == {"decision": "deny"}
        else:
            assert "Request failed" in err

        # 2. Setup 1
        call_op(s_dir, op="setup", owners={"d1": "alice"}, contents={"d1": "v1"}, disabled=[], key_material="k1")
        r1 = call_op(s_dir, op="read", actor="alice", asset="d1", request_id="r1")
        assert r1.get("decision") == "allow"

        # 3. Setup 2 in same dir -> fresh state
        call_op(s_dir, op="setup", owners={"d2": "bob"}, contents={"d2": "v2"}, disabled=[], key_material="k2")
        r_old = call_op(s_dir, op="read", actor="alice", asset="d1", request_id="r_old")
        assert r_old.get("decision") == "deny"
        r_new = call_op(s_dir, op="read", actor="bob", asset="d2", request_id="r_new")
        assert r_new.get("decision") == "allow"

        # 4. Revoking unknown actor does not crash
        call_op(s_dir, op="revoke", actor="nonexistent_ghost")

        # 5. Duplicate request_id: audit returns the most recent read decision
        call_op(s_dir, op="read", actor="bob", asset="d2", request_id="dup-req-id")
        # Revoke bob and read again with same request_id
        call_op(s_dir, op="revoke", actor="bob")
        call_op(s_dir, op="read", actor="bob", asset="d2", request_id="dup-req-id")
        audit_res = call_op(s_dir, op="audit", request_id="dup-req-id")
        assert audit_res == {"request_id": "dup-req-id", "decision": "deny"}


def test_attack_log_tamper():
    """Attack: log line tampering, tail deletion, corrupt/deleted checkpoint, and line reordering."""
    with tempfile.TemporaryDirectory(prefix="t4-atk-tamper-") as temp_dir:
        s_dir = Path(temp_dir)
        call_op(s_dir, op="setup", owners={"d1": "alice"}, contents={"d1": "secret"}, disabled=[], key_material="seed")
        call_op(s_dir, op="read", actor="alice", asset="d1", request_id="r1")
        call_op(s_dir, op="read", actor="alice", asset="d1", request_id="r2")
        call_op(s_dir, op="read", actor="alice", asset="d1", request_id="r3")

        log_path = s_dir / "audit.log"
        cp_path = s_dir / "checkpoint.json"
        orig_log = log_path.read_text(encoding="utf-8")
        orig_cp = cp_path.read_text(encoding="utf-8")

        # 1. Edit one character in a line -> verify fails and names the line
        lines = orig_log.splitlines()
        e2 = json.loads(lines[1])
        e2["actor"] = "attacker"
        lines[1] = json.dumps(e2)
        log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        rep1 = audit.verify_audit_log(s_dir)
        assert rep1["valid"] is False
        assert rep1["bad_line"] == 2
        assert "Hash mismatch" in rep1["reason"]

        # Restore
        log_path.write_text(orig_log, encoding="utf-8")

        # 2. Delete last line -> detected via checkpoint
        lines = orig_log.splitlines()
        log_path.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")
        rep2 = audit.verify_audit_log(s_dir)
        assert rep2["valid"] is False
        assert "Tail truncation detected" in rep2["reason"]

        # Restore
        log_path.write_text(orig_log, encoding="utf-8")

        # 3. Corrupt or delete checkpoint.json -> detected
        cp_path.unlink()
        rep3 = audit.verify_audit_log(s_dir)
        assert rep3["valid"] is False
        assert "Missing checkpoint" in rep3["reason"]

        # Corrupt signature
        cp_path.write_text(orig_cp, encoding="utf-8")
        cp_data = json.loads(orig_cp)
        cp_data["sig"] = "00" * 3309
        cp_path.write_text(json.dumps(cp_data), encoding="utf-8")
        rep4 = audit.verify_audit_log(s_dir)
        assert rep4["valid"] is False
        assert "signature verification failed" in rep4["reason"]

        # 4. Reorder two lines -> detected
        cp_path.write_text(orig_cp, encoding="utf-8")
        lines = orig_log.splitlines()
        lines[1], lines[2] = lines[2], lines[1]
        log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        rep5 = audit.verify_audit_log(s_dir)
        assert rep5["valid"] is False
        assert rep5["bad_line"] in (2, 3)


def test_attack_backup():
    """Attack: damaged backup, bad signature, older key_version, and un-revocation attempts."""
    with tempfile.TemporaryDirectory(prefix="t4-atk-backup-") as temp_dir:
        s_dir = Path(temp_dir)
        os.environ["TRACK4_STATE_DIR"] = str(s_dir)

        call_op(s_dir, op="setup", owners={"d1": "alice", "d2": "bob"}, contents={"d1": "data1", "d2": "data2"}, disabled=[], key_material="sec")
        initial_state = store.load_state()

        # Create valid initial backup
        bak_file = s_dir / "valid_bak.json"
        backup.create_backup(bak_file)

        # 1. Damaged backup (content modified) refused
        tampered_content = json.loads(bak_file.read_text(encoding="utf-8"))
        tampered_content["content"]["state"]["contents"]["d1"] = "forged"
        t_file = s_dir / "tampered.json"
        t_file.write_text(json.dumps(tampered_content), encoding="utf-8")
        with pytest.raises(backup.BackupError, match="hash mismatch"):
            backup.restore_backup(t_file)
        assert store.load_state() == initial_state

        # 2. Bad signature refused
        bad_sig = json.loads(bak_file.read_text(encoding="utf-8"))
        bad_sig["signature"] = "ff" * 3309
        bs_file = s_dir / "badsig.json"
        bs_file.write_text(json.dumps(bad_sig), encoding="utf-8")
        with pytest.raises(backup.BackupError, match="signature verification failed"):
            backup.restore_backup(bs_file)
        assert store.load_state() == initial_state

        # 3. Older key_version refused
        call_op(s_dir, op="rotate", key_material="new_sec")
        state_v2 = store.load_state()
        assert state_v2["key_version"] == 2

        with pytest.raises(backup.BackupError, match="older than current"):
            backup.restore_backup(bak_file)
        assert store.load_state() == state_v2

        # 4. Old valid backup can NEVER un-revoke anyone
        # Create backup while bob is NOT revoked
        bak_v2 = s_dir / "bak_v2.json"
        backup.create_backup(bak_v2)

        # Revoke bob in current state
        call_op(s_dir, op="revoke", actor="bob")
        r_denied = call_op(s_dir, op="read", actor="bob", asset="d2", request_id="rb1")
        assert r_denied.get("decision") == "deny"

        # Restore bak_v2
        backup.restore_backup(bak_v2)

        # Bob MUST STILL BE DENIED
        r_post = call_op(s_dir, op="read", actor="bob", asset="d2", request_id="rb2")
        assert r_post.get("decision") == "deny"
        assert "body" not in r_post


def test_attack_concurrency():
    """Attack: launch 8 adapter processes simultaneously (reads + revoke) -> no corruption, no deadlock, finishes < 8s."""
    with tempfile.TemporaryDirectory(prefix="t4-atk-concurr-") as temp_dir:
        s_dir = Path(temp_dir)
        call_op(
            s_dir,
            op="setup",
            owners={f"doc{i}": f"user{i}" for i in range(8)},
            contents={f"doc{i}": f"secret{i}" for i in range(8)},
            disabled=[],
            key_material="concurr_seed",
        )

        requests = [
            {"op": "read", "actor": "user0", "asset": "doc0", "request_id": "c-req-0"},
            {"op": "read", "actor": "user1", "asset": "doc1", "request_id": "c-req-1"},
            {"op": "read", "actor": "user2", "asset": "doc2", "request_id": "c-req-2"},
            {"op": "revoke", "actor": "user0", "request_id": "c-rev-user0"},
            {"op": "read", "actor": "user3", "asset": "doc3", "request_id": "c-req-3"},
            {"op": "read", "actor": "user4", "asset": "doc4", "request_id": "c-req-4"},
            {"op": "read", "actor": "user5", "asset": "doc5", "request_id": "c-req-5"},
            {"op": "read", "actor": "user6", "asset": "doc6", "request_id": "c-req-6"},
        ]

        t0 = time.monotonic()
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(execute_adapter, req, s_dir) for req in requests]
            results = [f.result() for f in futures]
        t1 = time.monotonic()

        elapsed = t1 - t0
        assert elapsed < 8.0, f"Concurrent execution took {elapsed:.2f}s (must finish under 8s)"

        for rc, stdout, stderr in results:
            assert rc == 0, f"Subprocess failed with code {rc}: {stderr}"

        # Confirm state and audit log are completely intact and valid
        report = audit.verify_audit_log(s_dir)
        assert report["valid"] is True, f"Audit log corrupted under concurrency: {report}"
        assert report["entries_count"] == 9  # 1 setup + 8 concurrent requests

        with open(s_dir / "state.json", "r", encoding="utf-8") as sf:
            state = json.load(sf)
        assert state is not None
        assert "user0" in state.get("revoked", [])


def test_attack_leak_check():
    """Attack: grep all artifacts for fake key_material and body text to confirm zero information leakage."""
    with tempfile.TemporaryDirectory(prefix="t4-atk-leak-") as temp_dir:
        s_dir = Path(temp_dir)
        fake_key = "SYNTHETIC_LEAK_MARKER_KEY_XYZ_987654"
        fake_body = "HIGHLY_CLASSIFIED_PAYLOAD_BODY_TEXT_12345"

        initial = {
            "op": "setup",
            "owners": {"secret_doc": "alice"},
            "contents": {"secret_doc": fake_body},
            "disabled": [],
            "key_material": fake_key,
        }
        rc1, out1, err1 = execute_adapter(initial, s_dir)
        assert rc1 == 0

        read_req = {"op": "read", "actor": "alice", "asset": "secret_doc", "request_id": "r-leak-1"}
        rc2, out2, err2 = execute_adapter(read_req, s_dir)
        assert rc2 == 0

        # Denied read
        read_bad = {"op": "read", "actor": "bob", "asset": "secret_doc", "request_id": "r-leak-2"}
        rc3, out3, err3 = execute_adapter(read_bad, s_dir)
        assert rc3 == 0

        # Check stdout/stderr of setup
        assert fake_key not in out1 and fake_key not in err1
        assert fake_key not in out2 and fake_key not in err2
        assert fake_key not in out3 and fake_key not in err3

        # Check audit.log
        audit_content = (s_dir / "audit.log").read_text(encoding="utf-8")
        assert fake_key not in audit_content, "key_material leaked into audit.log!"
        assert fake_body not in audit_content, "body text leaked into audit.log!"

        # Check checkpoint.json
        cp_content = (s_dir / "checkpoint.json").read_text(encoding="utf-8")
        assert fake_key not in cp_content, "key_material leaked into checkpoint.json!"
        assert fake_body not in cp_content, "body text leaked into checkpoint.json!"

        # Check journal.json if present
        j_path = s_dir / "journal.json"
        if j_path.exists():
            j_content = j_path.read_text(encoding="utf-8")
            assert fake_key not in j_content
            assert fake_body not in j_content

        # key_material must be present in state.json only
        state_content = (s_dir / "state.json").read_text(encoding="utf-8")
        assert fake_key in state_content


def test_attack_messaging_end_to_end():
    """Attack: real ML-KEM-768 round-trip, HMAC proof verification, revoked deny, invalid keys, missing helper simulation."""
    with tempfile.TemporaryDirectory(prefix="t4-atk-msg-") as temp_dir:
        s_dir = Path(temp_dir)
        body = "Top-Secret Quantum Asset Payload"
        call_op(s_dir, op="setup", owners={"doc_kem": "alice", "doc_peer": "bob"}, contents={"doc_kem": body, "doc_peer": "peer data"}, disabled=[], key_material="sec")

        pk, sk = ml_kem_generate_keypair()
        pk_b64 = base64.b64encode(pk).decode("ascii")
        challenge = "fresh-session-challenge-1234"

        # 1. Allowed owner -> returns ciphertext & proof
        resp = call_op(
            s_dir,
            op="protected_read",
            actor="alice",
            asset="doc_kem",
            challenge=challenge,
            public_key=pk_b64,
            request_id="req-pr-1",
        )
        assert "ciphertext" in resp
        assert "proof" in resp

        ct_bytes = base64.b64decode(resp["ciphertext"], validate=True)
        shared_secret = ml_kem_decrypt(sk, ct_bytes)
        expected_proof = hmac.new(shared_secret, (challenge + body).encode("utf-8"), hashlib.sha256).hexdigest()
        assert hmac.compare_digest(resp["proof"], expected_proof)

        # 2. Revoked owner -> deny with no ciphertext
        call_op(s_dir, op="revoke", actor="alice")
        resp_rev = call_op(
            s_dir,
            op="protected_read",
            actor="alice",
            asset="doc_kem",
            challenge="ch-rev",
            public_key=pk_b64,
            request_id="req-pr-rev",
        )
        assert resp_rev == {"decision": "deny"}
        assert "ciphertext" not in resp_rev

        # 3. Garbage / wrong-length keys -> deny and no crash
        for bad_key in ["not_base64!", base64.b64encode(b"too_short").decode(), base64.b64encode(b"X" * (KEM_PK_SIZE + 10)).decode()]:
            resp_bad = call_op(
                s_dir,
                op="protected_read",
                actor="bob",
                asset="doc_peer",
                challenge="ch-bad",
                public_key=bad_key,
                request_id="req-pr-bad",
            )
            assert resp_bad == {"decision": "deny"}
            assert "ciphertext" not in resp_bad

        # 4. Helper import missing simulated -> returns deny
        test_script = f"""
import os, sys, json
sys.path.insert(0, r"{REPO_ROOT}")
# Simulate missing helper
sys.modules['messaging.protected_read'] = None
from team_app import dispatch

os.environ['TRACK4_STATE_DIR'] = r"{s_dir}"
req = {{"op": "protected_read", "actor": "bob", "asset": "doc_peer", "challenge": "c", "public_key": "{pk_b64}", "request_id": "r-sim"}}
res = dispatch(req)
print(json.dumps(res))
"""
        proc = subprocess.run([sys.executable, "-c", test_script], capture_output=True, text=True)
        assert proc.returncode == 0
        parsed = json.loads(proc.stdout.strip())
        assert parsed == {"decision": "deny"}
