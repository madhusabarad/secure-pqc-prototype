"""Performance and log growth benchmarking script.

Measures p50/p95 latency over 200 fresh-process invocations per operation
(matching the judging harness) and reports audit log storage growth.
"""

import json
import os
from pathlib import Path
import statistics
import subprocess
import sys
import tempfile
import time

REPO_ROOT = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(REPO_ROOT))

ENTRY_SCRIPT = REPO_ROOT / "track4_service.py"
NUM_RUNS = 200


def run_op(request: dict, state_dir: Path) -> tuple[float, dict]:
    """Execute a single operation in a fresh process and return elapsed time in ms."""
    env = os.environ.copy()
    env["TRACK4_STATE_DIR"] = str(state_dir)
    env["TMPDIR"] = str(state_dir)
    env["TEMP"] = str(state_dir)
    env["TMP"] = str(state_dir)

    cmd = [sys.executable, "-B", str(ENTRY_SCRIPT)]
    t0 = time.perf_counter()
    p = subprocess.Popen(
        cmd,
        cwd=REPO_ROOT,
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stdout, stderr = p.communicate(input=json.dumps(request).encode("utf-8"), timeout=15)
    t1 = time.perf_counter()
    elapsed_ms = (t1 - t0) * 1000.0
    if p.returncode != 0:
        raise RuntimeError(f"Operation failed with code {p.returncode}: {stderr.decode()}")
    return elapsed_ms, json.loads(stdout.decode())


def benchmark():
    print(f"Benchmarking Part C Adapter ({NUM_RUNS} runs per operation, fresh subprocess per call)...")
    results = {}

    with tempfile.TemporaryDirectory(prefix="t4-bench-") as temp_dir:
        state_dir = Path(temp_dir)

        # 1. Setup benchmark
        setup_times = []
        for i in range(NUM_RUNS):
            req = {
                "op": "setup",
                "owners": {f"asset_{j}": f"user_{j}" for j in range(10)},
                "contents": {f"asset_{j}": f"content_payload_{j}" for j in range(10)},
                "disabled": ["user_disabled"],
                "key_material": "synthetic-perf-seed",
            }
            elapsed, _ = run_op(req, state_dir)
            setup_times.append(elapsed)
        results["setup"] = setup_times

        # Re-initialize for subsequent tests
        run_op(
            {
                "op": "setup",
                "owners": {"doc1": "alice", "doc2": "bob"},
                "contents": {"doc1": "alice secret payload", "doc2": "bob secret payload"},
                "disabled": ["bad_actor"],
                "key_material": "synthetic-perf-seed",
            },
            state_dir,
        )

        # 2. Read (allowed)
        read_allow_times = []
        for i in range(NUM_RUNS):
            req = {"op": "read", "actor": "alice", "asset": "doc1", "request_id": f"req-bench-allow-{i}"}
            elapsed, _ = run_op(req, state_dir)
            read_allow_times.append(elapsed)
        results["read_allow"] = read_allow_times

        # 3. Read (denied - wrong owner or disabled)
        read_deny_times = []
        for i in range(NUM_RUNS):
            req = {"op": "read", "actor": "bad_actor", "asset": "doc1", "request_id": f"req-bench-deny-{i}"}
            elapsed, _ = run_op(req, state_dir)
            read_deny_times.append(elapsed)
        results["read_deny"] = read_deny_times

        # 4. Audit lookups
        audit_times = []
        for i in range(NUM_RUNS):
            req = {"op": "audit", "request_id": f"req-bench-allow-{i}"}
            elapsed, _ = run_op(req, state_dir)
            audit_times.append(elapsed)
        results["audit"] = audit_times

        # 5. Revocations
        revoke_times = []
        for i in range(NUM_RUNS):
            req = {"op": "revoke", "actor": f"user_to_revoke_{i}", "request_id": f"rev-bench-{i}"}
            elapsed, _ = run_op(req, state_dir)
            revoke_times.append(elapsed)
        results["revoke"] = revoke_times

        # Measure log file size and checkpoint size
        log_path = state_dir / "audit.log"
        cp_path = state_dir / "checkpoint.json"
        log_size_bytes = log_path.stat().st_size if log_path.exists() else 0
        cp_size_bytes = cp_path.stat().st_size if cp_path.exists() else 0
        total_events = len(log_path.read_text(encoding="utf-8").splitlines()) if log_path.exists() else 0

    print("\n" + "=" * 65)
    print(f"{'Operation':<18} | {'Count':<7} | {'p50 (ms)':<12} | {'p95 (ms)':<12}")
    print("-" * 65)
    for op_name, times in results.items():
        sorted_times = sorted(times)
        p50 = statistics.median(sorted_times)
        p95 = statistics.quantiles(sorted_times, n=20)[18] if len(sorted_times) >= 20 else sorted_times[-1]
        print(f"{op_name:<18} | {len(times):<7} | {p50:<12.2f} | {p95:<12.2f}")
    print("=" * 65)
    print(f"\nAudit Log Storage Metrics after {total_events} events:")
    print(f"  audit.log size    : {log_size_bytes} bytes ({log_size_bytes / 1024.0:.2f} KiB)")
    print(f"  checkpoint.json   : {cp_size_bytes} bytes ({cp_size_bytes / 1024.0:.2f} KiB)")
    avg_entry_size = log_size_bytes / max(1, total_events)
    print(f"  average entry size: {avg_entry_size:.1f} bytes/event")


if __name__ == "__main__":
    benchmark()
