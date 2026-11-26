"""Optional local demo frontend server for Track 4 hackathon project.

Binds exclusively to 127.0.0.1:8000 and exposes a strictly limited set of fixed
demo actions executing against the real track4_service adapter process.
Standard library only: http.server, subprocess, json, secrets, tempfile, sys, os, pathlib.
"""

from __future__ import annotations

import atexit
import http.server
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
from typing import Any, Dict, Optional, Tuple

HOST = "127.0.0.1"
PORT = 8000

REPO_ROOT = Path(__file__).resolve().parent.parent
INDEX_HTML_PATH = Path(__file__).resolve().parent / "index.html"

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
}

ALLOWED_STEPS = {
    "setup",
    "owner_read",
    "revoke_owner",
    "owner_read_again",
    "audit",
    "second_owner_read",
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

    raise ValueError(f"Unknown step: {step_name}")


def run_adapter_step(step_name: str) -> Dict[str, Any]:
    """Execute a step by invoking track4_service.py in a fresh process."""
    try:
        raw_req, sanitized_req = build_step_request(step_name)
    except Exception as exc:
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
        # Responses without a decision (e.g. setup: {"ready": True}, revoke: {})
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


class DemoHandler(http.server.BaseHTTPRequestHandler):
    """Single-purpose HTTP handler serving only index.html and fixed API endpoints."""

    def log_message(self, format: str, *args: Any) -> None:
        # Minimal logging; never echo request payloads or secrets
        sys.stderr.write(f"[{self.log_date_time_string()}] {format % args}\n")

    def _send_bytes(
        self,
        status: int,
        content_type: str,
        body: bytes,
    ) -> None:
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
        if self.path == "/":
            if not INDEX_HTML_PATH.is_file():
                self._send_bytes(500, "text/plain; charset=utf-8", b"index.html missing\n")
                return
            try:
                html_bytes = INDEX_HTML_PATH.read_bytes()
                self._send_bytes(200, "text/html; charset=utf-8", html_bytes)
            except Exception:
                self._send_bytes(500, "text/plain; charset=utf-8", b"Failed reading index.html\n")
        else:
            self._send_not_found()

    def do_POST(self) -> None:
        # Discard any optional body sent by client
        content_len = int(self.headers.get("Content-Length", 0))
        if content_len > 0:
            self.rfile.read(min(content_len, 4096))

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
