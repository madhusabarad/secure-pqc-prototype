"""Crash recovery injection harness.

Simulates hard power-cuts / process crashes at distinct transactional checkpoints:
- after_intent: crash immediately after writing journal.json
- after_commit: crash immediately after atomic os.replace of state.json
- before_audit: crash right before audit log append
- after_audit: crash right after audit log append, before journal removal

Asserts:
- State remains consistent
- Revoked actor stays revoked across all crash scenarios
- Audit event is recorded exactly once (idempotent recovery)
"""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

# Ensure parent directory is on sys.path
REPO_ROOT = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(REPO_ROOT))

ENTRY_SCRIPT = REPO_ROOT / "track4_service.py"


def run_process(request: dict, state_dir: Path, crash_at: str = None) -> tuple[int, dict, str]:
    """Execute one adapter request in a new process, optionally injecting a crash."""
    env = os.environ.copy()
    env["TRACK4_STATE_DIR"] = str(state_dir)
    env["TMPDIR"] = str(state_dir)
    env["TEMP"] = str(state_dir)
    env["TMP"] = str(state_dir)
    if crash_at:
        env["TRACK4_CRASH_AT"] = crash_at
    else:
        env.pop("TRACK4_CRASH_AT", None)

    cmd = [sys.executable, "-B", str(ENTRY_SCRIPT)]
    p = subprocess.Popen(
        cmd,
        cwd=REPO_ROOT,
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stdout, stderr = p.communicate(input=json.dumps(request).encode("utf-8"), timeout=10)
    response = {}
    if stdout.strip():
        try:
            response = json.loads(stdout.decode("utf-8"))
        except Exception:
            pass
    return p.returncode, response, stderr.decode("utf-8")


def test_crash_step(crash_hook: str):
    """Test a specific crash point during revocation."""
    print(f"\n--- Testing crash injection at: {crash_hook} ---")
    with tempfile.TemporaryDirectory(prefix=f"t4-crash-{crash_hook}-") as temp_dir:
        state_dir = Path(temp_dir)

        # 1. Setup initial state
        setup_req = {
            "op": "setup",
            "owners": {"doc1": "alice", "doc2": "bob"},
            "contents": {"doc1": "alice secret", "doc2": "bob secret"},
            "disabled": [],
            "key_material": "marker-seed-crash-test",
        }
        rc, resp, err = run_process(setup_req, state_dir)
        assert rc == 0 and resp.get("ready") is True, f"Setup failed: {err}"

        # 2. Confirm alice can read doc1 initially
        read_req = {"op": "read", "actor": "alice", "asset": "doc1", "request_id": "req-alice-init"}
        rc, resp, err = run_process(read_req, state_dir)
        assert rc == 0 and resp.get("decision") == "allow" and resp.get("body") == "alice secret"

        # 3. Trigger revoke with crash injection
        revoke_req = {"op": "revoke", "actor": "alice", "request_id": f"rev-{crash_hook}"}
        rc, resp, err = run_process(revoke_req, state_dir, crash_at=crash_hook)
        print(f"Crashed process returned exit code: {rc} (expected 42)")
        assert rc == 42, f"Expected injected crash exit code 42, got {rc}"

        # 4. Restart process: perform read attempt as alice (triggers recovery)
        read_post = {"op": "read", "actor": "alice", "asset": "doc1", "request_id": f"req-alice-post-{crash_hook}"}
        rc, resp, err = run_process(read_post, state_dir)
        assert rc == 0, f"Post-crash read failed: {err}"
        assert resp.get("decision") == "deny", f"Alice was not denied after crash recovery! Got: {resp}"
        assert "body" not in resp, "Denied response disclosed asset body!"
        print("PASS: Revocation persisted and actor is denied access.")

        # 5. Confirm unaffected peer bob still has access
        bob_read = {"op": "read", "actor": "bob", "asset": "doc2", "request_id": f"req-bob-{crash_hook}"}
        rc, resp, err = run_process(bob_read, state_dir)
        assert rc == 0 and resp.get("decision") == "allow" and resp.get("body") == "bob secret"
        print("PASS: Unaffected peer retains authorized access.")

        # 6. Verify audit log integrity and count revoke events
        log_file = state_dir / "audit.log"
        assert log_file.exists(), "audit.log is missing"
        entries = [json.loads(line) for line in log_file.read_text(encoding="utf-8").splitlines() if line.strip()]

        revoke_events = [e for e in entries if e.get("action") == "revoke" and e.get("actor") == "alice"]
        assert len(revoke_events) == 1, f"Revoke event count expected 1, found {len(revoke_events)}"
        print(f"PASS: Revoke audit event recorded exactly once (correlation_id={revoke_events[0].get('correlation_id')}).")

        # 7. Check audit op lookup
        audit_req = {"op": "audit", "request_id": f"rev-{crash_hook}"}
        rc, resp, err = run_process(audit_req, state_dir)
        assert rc == 0 and resp.get("decision") in ("deny", "success"), f"Audit op lookup failed: {resp}"
        print("PASS: Audit query completed.")


def main():
    hooks = ["after_intent", "after_commit", "before_audit", "after_audit"]
    print("Starting Part C crash-recovery test suite across all 4 transaction boundaries...")
    for hook in hooks:
        test_crash_step(hook)
    print("\nALL 4 CRASH RECOVERY TESTS PASSED!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
