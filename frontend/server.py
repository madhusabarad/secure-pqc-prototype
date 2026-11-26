"""Full local demo frontend server for Track 4 hackathon project.

Binds exclusively to 127.0.0.1:8000 and exposes endpoints for:
1. Access control & lost-device story (setup, read, revoke, reenrol, rotate, audit).
2. Cybersecurity anomaly detector (synthetic events, explainable alerts, metrics).
3. PQC secure messaging demo (Part A hybrid key exchange, replay, chunking).
4. Tamper-evident audit log inspection and cryptographic verification.

Standard library only: http.server, subprocess, json, secrets, tempfile, sys, os, pathlib.
"""

from __future__ import annotations

import atexit
from datetime import datetime, timezone
import http.server
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Dict, List, Optional, Tuple

HOST = "127.0.0.1"
PORT = 8000

REPO_ROOT = Path(__file__).resolve().parent.parent
INDEX_HTML_PATH = Path(__file__).resolve().parent / "index.html"

# Add repo root to python path for internal imports
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app import audit
from detector import detector as sec_detector
from detector.evaluator import evaluate_detector
from detector.time_order import correct_event_time, is_order_uncertain
from simdata.generator import generate_events, load_approvals

# Temporary state directory for runtime adapter isolation (never inside repo)
STATE_DIR = tempfile.mkdtemp(prefix="t4_frontend_state_")


def _cleanup_state_dir(target_dir: str) -> None:
    p = Path(target_dir)
    if not p.exists():
        return
    for root, dirs, files in os.walk(p, topdown=False):
        for f in files:
            fp = Path(root) / f
            try:
                fp.chmod(0o777)
            except OSError:
                pass
            try:
                fp.unlink(missing_ok=True)
            except OSError:
                pass
        for d in dirs:
            dp = Path(root) / d
            try:
                dp.rmdir()
            except OSError:
                pass
    try:
        p.rmdir()
    except OSError:
        pass


atexit.register(_cleanup_state_dir, STATE_DIR)

ADAPTER_ENV = os.environ.copy()
ADAPTER_ENV["TRACK4_STATE_DIR"] = STATE_DIR
ADAPTER_ENV["TMPDIR"] = STATE_DIR
ADAPTER_ENV["TEMP"] = STATE_DIR
ADAPTER_ENV["TMP"] = STATE_DIR

# Generated key material for demo session; never hard-coded and never exposed.
DEMO_KEY_MATERIAL = secrets.token_hex(16)

# Server-side state tracking correlation IDs for demo steps
DEMO_STATE: Dict[str, Optional[str]] = {
    "last_denied_read_id": None,
    "last_reenrol_id": None,
}

ALLOWED_STEPS = {
    "setup",
    "owner_read",
    "revoke_owner",
    "owner_read_again",
    "audit",
    "second_owner_read",
    "reenrol_owner",
    "owner_read_post_reenrol",
    "rotate_key",
}


def build_step_request(step_name: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Build adapter request payload and a sanitized version for the client."""
    if step_name == "setup":
        payload = {
            "op": "setup",
            "owners": {
                "report-1": "user-alex",
                "report-2": "user-blair",
            },
            "contents": {
                "report-1": "Alex confidential project notes.",
                "report-2": "Blair strategic quarterly plan.",
            },
            "disabled": [],
            "key_material": DEMO_KEY_MATERIAL,
        }
        sanitized = dict(payload)
        sanitized["key_material"] = "[hidden]"
        return payload, sanitized

    elif step_name == "owner_read":
        req_id = f"req-{secrets.token_hex(6)}"
        payload = {
            "op": "read",
            "actor": "user-alex",
            "asset": "report-1",
            "request_id": req_id,
        }
        return payload, dict(payload)

    elif step_name == "revoke_owner":
        req_id = f"req-rev-{secrets.token_hex(6)}"
        payload = {
            "op": "revoke",
            "actor": "user-alex",
            "request_id": req_id,
        }
        return payload, dict(payload)

    elif step_name == "owner_read_again":
        req_id = f"req-read2-{secrets.token_hex(6)}"
        DEMO_STATE["last_denied_read_id"] = req_id
        payload = {
            "op": "read",
            "actor": "user-alex",
            "asset": "report-1",
            "request_id": req_id,
        }
        return payload, dict(payload)

    elif step_name == "audit":
        audit_id = DEMO_STATE.get("last_denied_read_id") or "req-audit-unrecorded"
        payload = {
            "op": "audit",
            "request_id": audit_id,
        }
        return payload, dict(payload)

    elif step_name == "second_owner_read":
        req_id = f"req-{secrets.token_hex(6)}"
        payload = {
            "op": "read",
            "actor": "user-blair",
            "asset": "report-2",
            "request_id": req_id,
        }
        return payload, dict(payload)

    elif step_name == "reenrol_owner":
        req_id = f"req-reenrol-{secrets.token_hex(6)}"
        DEMO_STATE["last_reenrol_id"] = req_id
        payload = {
            "op": "reenrol",
            "actor": "user-alex",
            "new_device": f"dev-quantum-{secrets.token_hex(4)}",
            "request_id": req_id,
        }
        return payload, dict(payload)

    elif step_name == "owner_read_post_reenrol":
        req_id = f"req-post-reenrol-{secrets.token_hex(6)}"
        payload = {
            "op": "read",
            "actor": "user-alex",
            "asset": "report-1",
            "request_id": req_id,
        }
        return payload, dict(payload)

    elif step_name == "rotate_key":
        req_id = f"req-rot-{secrets.token_hex(6)}"
        payload = {
            "op": "rotate",
            "key_material": secrets.token_hex(16),
            "request_id": req_id,
        }
        sanitized = dict(payload)
        sanitized["key_material"] = "[hidden-new-key]"
        return payload, sanitized

    raise ValueError(f"Unknown step: {step_name}")


def run_adapter_step(step_name: str) -> Dict[str, Any]:
    """Execute a step by invoking track4_service.py in a fresh process."""
    try:
        raw_req, sanitized_req = build_step_request(step_name)
    except Exception:
        return {
            "step": step_name,
            "request": {},
            "response": {"error": "Failed to construct step request"},
            "label": "ERROR",
        }

    try:
        proc = subprocess.run(
            [sys.executable, "-B", "track4_service.py"],
            input=json.dumps(raw_req),
            capture_output=True,
            text=True,
            timeout=8,
            cwd=str(REPO_ROOT),
            env=ADAPTER_ENV,
        )
    except subprocess.TimeoutExpired:
        return {
            "step": step_name,
            "request": sanitized_req,
            "response": {"error": "Adapter execution timed out"},
            "label": "ERROR",
        }
    except Exception:
        return {
            "step": step_name,
            "request": sanitized_req,
            "response": {"error": "Process execution error"},
            "label": "ERROR",
        }

    if proc.returncode != 0:
        return {
            "step": step_name,
            "request": sanitized_req,
            "response": {"error": f"Adapter exited with code {proc.returncode}"},
            "label": "ERROR",
        }

    try:
        resp_obj = json.loads(proc.stdout)
        if not isinstance(resp_obj, dict):
            return {
                "step": step_name,
                "request": sanitized_req,
                "response": {"error": "Adapter stdout is not a JSON object"},
                "label": "ERROR",
            }
    except Exception:
        return {
            "step": step_name,
            "request": sanitized_req,
            "response": {"error": "Failed to parse adapter stdout as JSON"},
            "label": "ERROR",
        }

    # Derive human-readable label
    if "decision" in resp_obj:
        decision = resp_obj["decision"]
        if decision == "allow":
            label = "ALLOW"
        elif decision == "deny":
            label = "DENY"
        else:
            label = "ERROR"
    else:
        label = "OK"

    return {
        "step": step_name,
        "request": sanitized_req,
        "response": resp_obj,
        "label": label,
    }


def run_messaging_demo() -> Dict[str, Any]:
    """Execute messaging.demo_part_a in a fresh process with fixed args."""
    demo_path = REPO_ROOT / "messaging" / "demo_part_a.py"
    if not demo_path.is_file():
        return {"lines": [], "error": "Module messaging.demo_part_a does not exist"}

    try:
        proc = subprocess.run(
            [sys.executable, "-B", "-m", "messaging.demo_part_a"],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=str(REPO_ROOT),
            env=ADAPTER_ENV,
        )
        if proc.returncode != 0:
            return {
                "lines": [],
                "error": f"Messaging demo exited with code {proc.returncode}",
            }
        lines = [line[:500] for line in proc.stdout.splitlines()][:50]
        return {"lines": lines}
    except subprocess.TimeoutExpired:
        return {"lines": [], "error": "Messaging demo execution timed out"}
    except Exception:
        return {"lines": [], "error": "Failed to run messaging demo process"}


def get_detector_metrics() -> Dict[str, Any]:
    """Run detector evaluation engine and return benchmark metrics."""
    return evaluate_detector(seed=42, count=1000)


def get_sample_events() -> List[Dict[str, Any]]:
    """Return a curated set of sample simulated security events for UI viewing."""
    events, _ = generate_events(seed=42, count=60)
    # Enrich with timestamp correction info
    enriched = []
    for evt in events[:50]:
        e = dict(evt)
        corr_time, rec_time, late_sec = correct_event_time(evt)
        e["corrected_time_utc"] = corr_time.isoformat()
        e["late_delay_sec"] = round(late_sec, 2)
        enriched.append(e)
    return enriched


def run_detector_on_events(events: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    """Run security detector and return explainable alerts."""
    if events is None:
        events, _ = generate_events(seed=42, count=100)
    return sec_detector.run(events)


def inject_attack(attack_type: str) -> Dict[str, Any]:
    """Inject a specific attack scenario and return the detector's alert response."""
    now_utc = datetime.now(timezone.utc).isoformat()
    evt_id = f"evt_inj_{secrets.token_hex(4)}"

    if attack_type == "privilege_escalation":
        event = {
            "event_id": evt_id,
            "event_time_utc": now_utc,
            "actor": "user07",
            "source_service": "portal",
            "target_service": "auth",
            "action": "role_change",
            "role_before": "user",
            "role_after": "superadmin",
            "approval_id": None,
            "source_clock_offset_ms": 120,
        }
    elif attack_type == "lateral_movement":
        event = {
            "event_id": evt_id,
            "event_time_utc": now_utc,
            "actor": "user03",
            "source_service": "portal",
            "target_service": "database_admin",
            "action": "query",
            "role_before": "analyst",
            "role_after": "analyst",
            "source_clock_offset_ms": -50,
        }
    else:
        return {"error": f"Unknown attack type: {attack_type}"}

    alerts = sec_detector.run([event])
    return {
        "injected_event": event,
        "alerts": alerts,
        "detected": len(alerts) > 0,
    }


def get_audit_log_entries() -> Dict[str, Any]:
    """Read audit.log and checkpoint.json from the active STATE_DIR."""
    state_path = Path(STATE_DIR)
    log_file = state_path / "audit.log"
    checkpoint_file = state_path / "checkpoint.json"

    entries = []
    if log_file.is_file():
        with open(log_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except Exception:
                        entries.append({"raw": line, "corrupted": True})

    checkpoint = None
    if checkpoint_file.is_file():
        try:
            with open(checkpoint_file, "r", encoding="utf-8") as f:
                checkpoint = json.load(f)
        except Exception:
            checkpoint = {"error": "Failed reading checkpoint"}

    return {
        "entries": entries,
        "count": len(entries),
        "checkpoint": checkpoint,
    }


def verify_active_audit_log() -> Dict[str, Any]:
    """Run cryptographic verification over the current audit log."""
    return audit.verify_audit_log(Path(STATE_DIR))


def run_tamper_test() -> Dict[str, Any]:
    """Create a temporary sandbox copy, tamper with one entry, and prove detection."""
    with tempfile.TemporaryDirectory(prefix="t4-tamper-test-") as temp_dir:
        src = Path(STATE_DIR)
        dst = Path(temp_dir)
        log_file = src / "audit.log"
        cp_file = src / "checkpoint.json"
        key_file = src / "audit_signing_key.json"

        if not log_file.is_file():
            return {"error": "No audit log exists yet. Run Setup first."}

        shutil.copy2(log_file, dst / "audit.log")
        if cp_file.is_file():
            shutil.copy2(cp_file, dst / "checkpoint.json")
        if key_file.is_file():
            shutil.copy2(key_file, dst / "audit_signing_key.json")

        # Read lines, modify one line
        lines = []
        with open(dst / "audit.log", "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip()]

        if not lines:
            return {"error": "Audit log is empty."}

        # Modify middle or last entry's action
        target_idx = max(0, len(lines) - 1)
        entry = json.loads(lines[target_idx])
        original_actor = entry.get("actor", "system")
        entry["actor"] = "attacker_spoofed"
        lines[target_idx] = json.dumps(entry, sort_keys=True)

        with open(dst / "audit.log", "w", encoding="utf-8") as f:
            for l in lines:
                f.write(l + "\n")

        # Verify the tampered directory
        report = audit.verify_audit_log(dst)
        return {
            "tampered_line": target_idx + 1,
            "original_actor": original_actor,
            "tampered_actor": "attacker_spoofed",
            "verification_report": report,
            "tamper_detected": not report.get("valid", True),
        }


class DemoHandler(http.server.BaseHTTPRequestHandler):
    """Single-purpose HTTP handler serving index.html and API endpoints."""

    def log_message(self, format: str, *args: Any) -> None:
        sys.stderr.write(f"[{self.log_date_time_string()}] {format % args}\n")

    def _send_bytes(self, status: int, content_type: str, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, status: int, data: Dict[str, Any]) -> None:
        encoded = json.dumps(data, indent=2).encode("utf-8")
        self._send_bytes(status, "application/json; charset=utf-8", encoded)

    def _send_not_found(self) -> None:
        self._send_bytes(404, "text/plain; charset=utf-8", b"Not Found\n")

    def do_GET(self) -> None:
        if self.path == "/" or self.path == "/index.html":
            if not INDEX_HTML_PATH.is_file():
                self._send_bytes(500, "text/plain; charset=utf-8", b"index.html missing\n")
                return
            try:
                html_bytes = INDEX_HTML_PATH.read_bytes()
                self._send_bytes(200, "text/html; charset=utf-8", html_bytes)
            except Exception:
                self._send_bytes(500, "text/plain; charset=utf-8", b"Failed reading index.html\n")

        elif self.path == "/api/detector/metrics":
            metrics = get_detector_metrics()
            self._send_json(200, metrics)

        elif self.path == "/api/detector/events":
            events = get_sample_events()
            self._send_json(200, {"events": events, "count": len(events)})

        elif self.path == "/api/audit/entries":
            audit_data = get_audit_log_entries()
            self._send_json(200, audit_data)

        else:
            self._send_not_found()

    def do_POST(self) -> None:
        content_len = int(self.headers.get("Content-Length", 0))
        body_data = {}
        if content_len > 0:
            raw_body = self.rfile.read(min(content_len, 65536))
            try:
                body_data = json.loads(raw_body.decode("utf-8"))
            except Exception:
                pass

        if self.path.startswith("/api/step/"):
            step_name = self.path[len("/api/step/"):]
            if step_name in ALLOWED_STEPS:
                result = run_adapter_step(step_name)
                self._send_json(200, result)
            else:
                self._send_not_found()

        elif self.path == "/api/messaging_demo":
            result = run_messaging_demo()
            self._send_json(200, result)

        elif self.path == "/api/detector/run":
            events_input = body_data.get("events")
            alerts = run_detector_on_events(events_input)
            self._send_json(200, {"alerts": alerts, "count": len(alerts)})

        elif self.path == "/api/detector/inject":
            attack_type = body_data.get("attack_type", "privilege_escalation")
            res = inject_attack(attack_type)
            self._send_json(200, res)

        elif self.path == "/api/audit/verify":
            res = verify_active_audit_log()
            self._send_json(200, res)

        elif self.path == "/api/audit/tamper_test":
            res = run_tamper_test()
            self._send_json(200, res)

        else:
            self._send_not_found()


def main() -> int:
    server = http.server.HTTPServer((HOST, PORT), DemoHandler)
    sys.stdout.write(f"Frontend demo server running at http://{HOST}:{PORT}\n")
    sys.stdout.flush()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        _cleanup_state_dir(STATE_DIR)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
