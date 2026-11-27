"""Crash recovery test harness using monkeypatched driver in scripts/ only.

Simulates process terminations at distinct transactional checkpoints:
- after_intent: crash immediately after writing journal.json
- after_commit: crash immediately after atomic os.replace of state.json
- before_audit: crash right before audit log append
- after_audit: crash right after audit log append, before journal removal

Asserts:
- State remains consistent (journal cleaned up, valid JSON)
- Revoked actor stays revoked across all crash scenarios
- Exactly one audit event for that revoke (idempotent roll-forward recovery)
- Unaffected peer retains authorized access
- Audit log cryptographic verification passes completely
"""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

REPO_ROOT = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(REPO_ROOT))

ENTRY_SCRIPT = REPO_ROOT / "track4_service.py"
CRASH_POINTS = ["after_intent", "after_commit", "before_audit", "after_audit"]


def run_adapter_process(request: dict, state_dir: Path) -> tuple[int, dict, str]:
    """Execute one adapter request through the real track4_service.py entry point."""
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
    stdout, stderr = p.communicate(input=json.dumps(request).encode("utf-8"), timeout=15)
    response = {}
    if stdout.strip():
        try:
            response = json.loads(stdout.decode("utf-8"))
        except Exception:
            pass
    return p.returncode, response, stderr.decode("utf-8")


def run_crash_driver(crash_point: str, actor: str, request_id: str, state_dir: Path) -> int:
    """Run child driver that monkeypatches and terminates with os._exit(42)."""
    env = os.environ.copy()
    env["TRACK4_STATE_DIR"] = str(state_dir)
    env["TMPDIR"] = str(state_dir)
    env["TEMP"] = str(state_dir)
    env["TMP"] = str(state_dir)

    cmd = [
        sys.executable,
        "-B",
        str(Path(__file__).resolve()),
        "--driver",
        crash_point,
        actor,
        request_id,
    ]
    p = subprocess.Popen(cmd, cwd=REPO_ROOT, env=env, stderr=subprocess.PIPE)
    _, stderr = p.communicate(timeout=15)
    return p.returncode


def _execute_driver(crash_point: str, actor: str, request_id: str) -> None:
    """Driver mode: monkeypatches auditlog and kills itself with os._exit(42)."""
    from auditlog import audit, recovery

    if crash_point == "after_intent":
        orig_begin = recovery.Journal.begin

        def patched_begin(self):
            orig_begin(self)
            os._exit(42)

        recovery.Journal.begin = patched_begin

    elif crash_point == "after_commit":
        orig_commit = recovery.Journal.commit

        def patched_commit(self, new_state):
            orig_commit(self, new_state)
            os._exit(42)

        recovery.Journal.commit = patched_commit

    elif crash_point == "before_audit":
        def patched_append(*args, **kwargs):
            os._exit(42)

        audit.append_event = patched_append

    elif crash_point == "after_audit":
        def patched_complete(self):
            os._exit(42)

        recovery.Journal.complete = patched_complete

    else:
        sys.exit(1)

    # Execute the revocation with monkeypatched crash
    recovery.execute_revoke(actor, request_id=request_id)
    # If it didn't exit, fail with code 1
    sys.exit(1)


def test_crash_point(crash_point: str) -> None:
    print(f"\n=== Testing crash injection at: {crash_point} ===")
    with tempfile.TemporaryDirectory(prefix=f"t4-crash-{crash_point}-") as temp_dir:
        state_dir = Path(temp_dir)
        corr_id = f"rev-{crash_point}"

        # 1. Setup initial state via real adapter
        setup_req = {
            "op": "setup",
            "owners": {"doc1": "alice", "doc2": "bob"},
            "contents": {"doc1": "alice secret data", "doc2": "bob secret data"},
            "disabled": [],
            "key_material": "marker-seed-crash-test",
        }
        rc, resp, err = run_adapter_process(setup_req, state_dir)
        assert rc == 0 and resp.get("ready") is True, f"Setup failed: {err}"

        # 2. Confirm alice can read doc1 initially
        read_req = {"op": "read", "actor": "alice", "asset": "doc1", "request_id": f"req-alice-init-{crash_point}"}
        rc, resp, err = run_adapter_process(read_req, state_dir)
        assert rc == 0 and resp.get("decision") == "allow" and resp.get("body") == "alice secret data"
        print(f"[{crash_point}] Initial authorized read: ALLOW")

        # 3. Inject crash during revocation via driver
        driver_rc = run_crash_driver(crash_point, "alice", corr_id, state_dir)
        print(f"[{crash_point}] Driver process exited with code: {driver_rc} (expected 42)")
        assert driver_rc == 42, f"Expected driver crash code 42, got {driver_rc}"

        # 4. Restart through real adapter: alice attempts to read (triggers recovery)
        read_post = {"op": "read", "actor": "alice", "asset": "doc1", "request_id": f"req-alice-post-{crash_point}"}
        rc, resp, err = run_adapter_process(read_post, state_dir)
        assert rc == 0, f"Post-crash adapter read failed: {err}"
        assert resp.get("decision") == "deny", f"Alice was not denied after recovery! Got: {resp}"
        assert "body" not in resp, "Denied response leaked body!"
        print(f"[{crash_point}] Post-crash read by revoked actor: DENIED (body protected)")

        # 5. Confirm unaffected peer bob still has access
        bob_read = {"op": "read", "actor": "bob", "asset": "doc2", "request_id": f"req-bob-{crash_point}"}
        rc, resp, err = run_adapter_process(bob_read, state_dir)
        assert rc == 0 and resp.get("decision") == "allow" and resp.get("body") == "bob secret data"
        print(f"[{crash_point}] Unaffected peer bob read: ALLOW")

        # 6. Audit check: query audit for the revoke request_id
        audit_req = {"op": "audit", "request_id": corr_id}
        rc, resp, err = run_adapter_process(audit_req, state_dir)
        assert rc == 0 and resp.get("decision") == "success"
        print(f"[{crash_point}] Audit lookup for {corr_id}: SUCCESS")

        # 7. Assert exactly ONE audit event exists for that revoke
        from auditlog import audit, store

        log_file = state_dir / "audit.log"
        assert log_file.exists(), "audit.log missing"
        matching_events = []
        with open(log_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)
                if entry.get("correlation_id") == corr_id:
                    matching_events.append(entry)

        assert len(matching_events) == 1, f"Expected exactly 1 audit event for {corr_id}, got {len(matching_events)}"
        assert matching_events[0]["action"] == "revoke"
        assert matching_events[0]["outcome"] == "success"
        print(f"[{crash_point}] Verified exactly 1 audit event for revoke correlation_id: PASS")

        # 8. Assert audit log cryptographic verification passes completely
        report = audit.verify_audit_log(state_dir)
        assert report["valid"] is True, f"Audit log verification failed: {report}"
        print(f"[{crash_point}] Audit log verification (hash chain & ML-DSA-65 sig): PASS")

        # 9. Verify state consistency
        state_file = state_dir / "state.json"
        assert state_file.exists(), "state.json missing"
        with open(state_file, "r", encoding="utf-8") as sf:
            state = json.load(sf)
        journal_file = state_dir / "journal.json"
        assert not journal_file.exists(), "Journal file was not cleaned up after recovery"
        assert "alice" in state.get("revoked", []), "Alice missing from revoked list in state.json"
        print(f"[{crash_point}] Consistent state verified: PASS")


def main():
    if len(sys.argv) >= 5 and sys.argv[1] == "--driver":
        _execute_driver(sys.argv[2], sys.argv[3], sys.argv[4])
        return 0

    print("Running Part C Crash Recovery Suite (4 transactional checkpoints)...")
    for cp in CRASH_POINTS:
        test_crash_point(cp)

    print("\nALL 4 CRASH RECOVERY TESTS PASSED!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
