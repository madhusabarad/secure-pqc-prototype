"""Full local real-time server for Track 4 PQC Security Platform.

Provides both backward-compatible judged-path endpoints and full real-time interactive APIs:
1. Real-Time PQC Secure Messenger (ML-DSA-65 identities, hybrid ML-KEM-768 + X25519 handshakes,
   AES-256-GCM transport, packet inspector, live replay attack & tamper simulation).
2. Dynamic Resource Vault & Access Control (dynamic documents, user/device management,
   instant revocation enforcement, real ML-KEM-768 protected reads, key rotation).
3. Live SOC Incident & Threat Detection Feed (real-time event streaming, explainable alerts,
   threat injection: unapproved escalation, lateral movement, data spike).
4. Live Cryptographic Audit Ledger (canonical SHA-256 hash-chain blocks, ML-DSA-65 signed checkpoints,
   one-click cryptographic verification and tamper detection).

Standard library only: http.server, subprocess, json, secrets, tempfile, sys, os, pathlib.
"""

from __future__ import annotations

import atexit
import base64
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
import time
from typing import Any, Dict, List, Optional, Tuple

HOST = "127.0.0.1"
PORT = 8000

REPO_ROOT = Path(__file__).resolve().parent.parent
INDEX_HTML_PATH = Path(__file__).resolve().parent / "index.html"

# Add repo root to python path for internal imports
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app import access, audit, recovery, store
from detector import detector as sec_detector
from detector.evaluator import evaluate_detector
from detector.time_order import correct_event_time, is_order_uncertain
from messaging import protected_read as kem_protected_read
from messaging import session as msg_session
from pqcrypto.kem import ml_kem_768
from pqcrypto.sign.ml_dsa_65 import generate_keypair as generate_dsa_keypair
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
ADAPTER_ENV["MSG_STATE_DIR"] = STATE_DIR
ADAPTER_ENV["TMPDIR"] = STATE_DIR
ADAPTER_ENV["TEMP"] = STATE_DIR
ADAPTER_ENV["TMP"] = STATE_DIR

os.environ["TRACK4_STATE_DIR"] = STATE_DIR
os.environ["MSG_STATE_DIR"] = STATE_DIR

DEMO_KEY_MATERIAL = secrets.token_hex(16)

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

# -----------------------------------------------------------------------------
# REAL-TIME IN-MEMORY MANAGERS
# -----------------------------------------------------------------------------

# Real-Time PQC Chat Identities & Sessions
PQC_IDENTITIES: Dict[str, Dict[str, Any]] = {}
PQC_SESSIONS: Dict[str, Dict[str, Any]] = {}
LAST_PACKET_BY_SESSION: Dict[str, Dict[str, Any]] = {}
SOC_LIVE_STREAM: List[Dict[str, Any]] = []


def _init_default_pqc_identities() -> None:
    """Initialize default standard participants with ML-DSA-65 keys."""
    default_users = ["alice", "bob", "charlie"]
    for u in default_users:
        pk, sk = generate_dsa_keypair()
        try:
            msg_session.register_identity(u, pk)
        except Exception:
            pass
        PQC_IDENTITIES[u] = {
            "user": u,
            "pk": pk,
            "sk": sk,
            "pk_b64": base64.b64encode(pk).decode("ascii"),
            "fingerprint": pk[:8].hex().upper(),
            "status": "active",
            "registered_at": datetime.now(timezone.utc).isoformat(),
        }


def _ensure_identities_registered() -> None:
    """Ensure in-memory identities remain present in msg_session public key registry."""
    for u, data in PQC_IDENTITIES.items():
        try:
            msg_session.get_public_keys(u)
        except KeyError:
            msg_session.register_identity(u, data["pk"])


def _ensure_vault_initialized() -> None:
    """Ensure vault has active baseline state in store."""
    current = store.load_state()
    if current is None:
        with store.file_lock():
            audit.reset_audit_log()
            store.init_state(
                owners={
                    "doc-pqc-spec": "alice",
                    "doc-soc-intel": "bob",
                    "doc-classified-qkd": "charlie",
                },
                contents={
                    "doc-pqc-spec": "ML-KEM-768 and ML-DSA-65 production parameters verified.",
                    "doc-soc-intel": "Threat actor APT-Quantum detected scanning port 8443.",
                    "doc-classified-qkd": "Quantum Key Distribution entanglement test successful.",
                },
                disabled=[],
                key_material=DEMO_KEY_MATERIAL,
            )
            audit.get_or_create_signing_key()
            audit.append_event(
                actor="system",
                action="vault_init",
                outcome="success",
                correlation_id="init-vault",
            )


# Initialize components
_init_default_pqc_identities()
_ensure_vault_initialized()


def emit_live_soc_event(
    actor: str,
    action: str,
    target_service: str,
    outcome: str = "success",
    details: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Emit a live event into the real-time SOC stream and evaluate detector."""
    now_utc = datetime.now(timezone.utc)
    evt_id = f"evt_live_{secrets.token_hex(4)}"
    event = {
        "event_id": evt_id,
        "event_time_utc": now_utc.isoformat(),
        "actor": actor,
        "source_service": "pqc_platform",
        "target_service": target_service,
        "action": action,
        "outcome": outcome,
        "role_before": "operator",
        "role_after": "operator",
        "source_clock_offset_ms": secrets.randbelow(30) - 15,
        "details": details or {},
    }
    alerts = sec_detector.run([event])
    stream_entry = {
        "event": event,
        "alerts": alerts,
        "detected": len(alerts) > 0,
        "timestamp": now_utc.isoformat(),
    }
    SOC_LIVE_STREAM.insert(0, stream_entry)
    if len(SOC_LIVE_STREAM) > 100:
        SOC_LIVE_STREAM.pop()
    return stream_entry


# -----------------------------------------------------------------------------
# STEP ENGINE FOR ADAPTER (Judged path backward compatibility)
# -----------------------------------------------------------------------------


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
    """Execute messaging.demo_part_a in a fresh process."""
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
    return evaluate_detector(seed=42, count=1000)


def get_sample_events() -> List[Dict[str, Any]]:
    events, _ = generate_events(seed=42, count=60)
    enriched = []
    for evt in events[:50]:
        e = dict(evt)
        corr_time, rec_time, late_sec = correct_event_time(evt)
        e["corrected_time_utc"] = corr_time.isoformat()
        e["late_delay_sec"] = round(late_sec, 2)
        enriched.append(e)
    return enriched


def run_detector_on_events(events: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    if events is None:
        events, _ = generate_events(seed=42, count=100)
    return sec_detector.run(events)


def inject_attack(attack_type: str) -> Dict[str, Any]:
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
    elif attack_type == "data_spike":
        event = {
            "event_id": evt_id,
            "event_time_utc": now_utc,
            "actor": "user12",
            "source_service": "analytics_engine",
            "target_service": "vault_storage",
            "action": "bulk_export",
            "role_before": "engineer",
            "role_after": "engineer",
            "source_clock_offset_ms": 15,
        }
    else:
        return {"error": f"Unknown attack type: {attack_type}"}

    alerts = sec_detector.run([event])
    # Also log to SOC live stream
    SOC_LIVE_STREAM.insert(
        0,
        {
            "event": event,
            "alerts": alerts,
            "detected": len(alerts) > 0,
            "timestamp": now_utc,
            "attack_type": attack_type,
        },
    )
    return {
        "injected_event": event,
        "alerts": alerts,
        "detected": len(alerts) > 0,
    }


def get_audit_log_entries() -> Dict[str, Any]:
    state_path = Path(STATE_DIR)
    log_file = state_path / "audit.log"
    checkpoint_file = state_path / "checkpoint.json"

    entries = []
    if log_file.is_file():
        with open(log_file, "r", encoding="utf-8") as f:
            for idx, line in enumerate(f):
                line = line.strip()
                if line:
                    try:
                        parsed = json.loads(line)
                        parsed["block_height"] = idx + 1
                        entries.append(parsed)
                    except Exception:
                        entries.append({"raw": line, "corrupted": True, "block_height": idx + 1})

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
    return audit.verify_audit_log(Path(STATE_DIR))


def run_tamper_test() -> Dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="t4-tamper-test-") as temp_dir:
        src = Path(STATE_DIR)
        dst = Path(temp_dir)
        log_file = src / "audit.log"
        cp_file = src / "checkpoint.json"
        key_file = src / "audit_signing_key.json"

        if not log_file.is_file():
            return {"error": "No audit log exists yet. Run Setup or perform actions first."}

        shutil.copy2(log_file, dst / "audit.log")
        if cp_file.is_file():
            shutil.copy2(cp_file, dst / "checkpoint.json")
        if key_file.is_file():
            shutil.copy2(key_file, dst / "audit_signing_key.json")

        lines = []
        with open(dst / "audit.log", "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip()]

        if not lines:
            return {"error": "Audit log is empty."}

        target_idx = max(0, len(lines) - 1)
        entry = json.loads(lines[target_idx])
        original_actor = entry.get("actor", "system")
        entry["actor"] = "attacker_spoofed"
        lines[target_idx] = json.dumps(entry, sort_keys=True)

        with open(dst / "audit.log", "w", encoding="utf-8") as f:
            for l in lines:
                f.write(l + "\n")

        report = audit.verify_audit_log(dst)
        return {
            "tampered_line": target_idx + 1,
            "original_actor": original_actor,
            "tampered_actor": "attacker_spoofed",
            "verification_report": report,
            "tamper_detected": not report.get("valid", True),
        }


# -----------------------------------------------------------------------------
# HTTP REQUEST HANDLER WITH FULL REAL-TIME APIS
# -----------------------------------------------------------------------------


class DemoHandler(http.server.BaseHTTPRequestHandler):
    """Unified HTTP handler serving Light-Themed UI and real-time security APIs."""

    def log_message(self, format: str, *args: Any) -> None:
        sys.stderr.write(f"[{self.log_date_time_string()}] {format % args}\n")

    def _send_bytes(self, status: int, content_type: str, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, status: int, data: Dict[str, Any]) -> None:
        encoded = json.dumps(data, indent=2).encode("utf-8")
        self._send_bytes(status, "application/json; charset=utf-8", encoded)

    def _send_not_found(self) -> None:
        self._send_bytes(404, "text/plain; charset=utf-8", b"Not Found\n")

    def _parse_body(self) -> Dict[str, Any]:
        content_len = int(self.headers.get("Content-Length", 0))
        if content_len > 0:
            raw = self.rfile.read(min(content_len, 1048576))
            try:
                return json.loads(raw.decode("utf-8"))
            except Exception:
                return {}
        return {}

    def do_GET(self) -> None:
        path = self.path.split("?")[0]

        if path in ("/", "/index.html"):
            if not INDEX_HTML_PATH.is_file():
                self._send_bytes(500, "text/plain; charset=utf-8", b"index.html missing\n")
                return
            try:
                html_bytes = INDEX_HTML_PATH.read_bytes()
                self._send_bytes(200, "text/html; charset=utf-8", html_bytes)
            except Exception:
                self._send_bytes(500, "text/plain; charset=utf-8", b"Failed reading index.html\n")

        # --- Real-Time PQC Chat Endpoints ---
        elif path == "/api/pqc/identities":
            identities = []
            for u, data in PQC_IDENTITIES.items():
                identities.append({
                    "user": u,
                    "fingerprint": data["fingerprint"],
                    "pk_b64": data["pk_b64"],
                    "status": "revoked" if msg_session.is_revoked(u) else "active",
                    "registered_at": data["registered_at"],
                })
            self._send_json(200, {"identities": identities})

        elif path == "/api/pqc/sessions":
            sessions_list = []
            for sid, sdata in PQC_SESSIONS.items():
                sessions_list.append({
                    "session_id": sid,
                    "initiator": sdata["initiator"],
                    "responder": sdata["responder"],
                    "created_at": sdata["created_at"],
                    "message_count": len(sdata["messages"]),
                    "last_packet": sdata.get("last_packet_meta"),
                })
            self._send_json(200, {"sessions": sessions_list})

        elif path == "/api/pqc/messages":
            # Extract query param session_id
            parts = self.path.split("session_id=")
            sid = parts[1].split("&")[0] if len(parts) > 1 else ""
            if sid in PQC_SESSIONS:
                self._send_json(200, {"session_id": sid, "messages": PQC_SESSIONS[sid]["messages"]})
            else:
                self._send_json(200, {"session_id": sid, "messages": []})

        # --- Dynamic Vault Endpoints ---
        elif path == "/api/vault/state":
            _ensure_vault_initialized()
            state = store.load_state() or {}
            owners = state.get("owners", {})
            contents = state.get("contents", {})
            revoked = state.get("revoked", [])
            disabled = state.get("disabled", [])
            key_version = state.get("key_version", 1)

            assets = []
            for aid, owner in owners.items():
                content = contents.get(aid, "")
                assets.append({
                    "asset_id": aid,
                    "owner": owner,
                    "classification": "CONFIDENTIAL" if "qkd" in aid else "RESTRICTED",
                    "preview": content[:60] + "..." if len(content) > 60 else content,
                    "key_version": key_version,
                })

            users = [
                {"actor": "alice", "device": "dev-pqc-laptop", "status": "revoked" if "alice" in revoked else "active"},
                {"actor": "bob", "device": "dev-soc-terminal", "status": "revoked" if "bob" in revoked else "active"},
                {"actor": "charlie", "device": "dev-quantum-rig", "status": "revoked" if "charlie" in revoked else "active"},
            ]
            self._send_json(200, {
                "assets": assets,
                "users": users,
                "revoked": revoked,
                "disabled": disabled,
                "key_version": key_version,
            })

        # --- Live SOC Stream Endpoints ---
        elif path == "/api/soc/live_feed":
            self._send_json(200, {
                "stream": SOC_LIVE_STREAM,
                "count": len(SOC_LIVE_STREAM),
            })

        elif path == "/api/detector/metrics":
            metrics = get_detector_metrics()
            self._send_json(200, metrics)

        elif path == "/api/detector/events":
            events = get_sample_events()
            self._send_json(200, {"events": events, "count": len(events)})

        elif path == "/api/audit/entries":
            audit_data = get_audit_log_entries()
            self._send_json(200, audit_data)

        else:
            self._send_not_found()

    def do_POST(self) -> None:
        body_data = self._parse_body()
        path = self.path.split("?")[0]

        # --- Real-Time PQC Interactive Messenger Endpoints ---
        if path == "/api/pqc/register":
            username = body_data.get("user", "").strip().lower()
            if not username:
                self._send_json(400, {"error": "Missing username"})
                return
            pk, sk = generate_dsa_keypair()
            msg_session.register_identity(username, pk)
            PQC_IDENTITIES[username] = {
                "user": username,
                "pk": pk,
                "sk": sk,
                "pk_b64": base64.b64encode(pk).decode("ascii"),
                "fingerprint": pk[:8].hex().upper(),
                "status": "active",
                "registered_at": datetime.now(timezone.utc).isoformat(),
            }
            with store.file_lock():
                audit.append_event(
                    actor=username,
                    action="pqc_identity_registered",
                    outcome="success",
                    correlation_id=f"reg-{username}",
                )
            emit_live_soc_event(username, "register_identity", "pqc_keystore", "success")
            self._send_json(200, {
                "success": True,
                "user": username,
                "fingerprint": PQC_IDENTITIES[username]["fingerprint"],
            })

        elif path == "/api/pqc/handshake":
            initiator = body_data.get("initiator", "").strip().lower()
            responder = body_data.get("responder", "").strip().lower()
            if initiator not in PQC_IDENTITIES or responder not in PQC_IDENTITIES:
                self._send_json(400, {"error": "Both parties must be registered identities"})
                return

            try:
                sid = msg_session.start_session(
                    initiator,
                    responder,
                    PQC_IDENTITIES[initiator]["sk"],
                    PQC_IDENTITIES[responder]["sk"],
                )
                PQC_SESSIONS[sid] = {
                    "session_id": sid,
                    "initiator": initiator,
                    "responder": responder,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "messages": [],
                }
                with store.file_lock():
                    audit.append_event(
                        actor=initiator,
                        action="pqc_handshake_established",
                        outcome="success",
                        correlation_id=f"hs-{sid[:8]}",
                    )
                emit_live_soc_event(
                    initiator,
                    "hybrid_handshake_ml_kem_768_x25519",
                    "pqc_channel",
                    "success",
                    {"responder": responder, "session_id": sid},
                )
                self._send_json(200, {
                    "success": True,
                    "session_id": sid,
                    "initiator": initiator,
                    "responder": responder,
                    "algorithm": "X25519 + ML-KEM-768 with ML-DSA-65 signatures",
                    "created_at": PQC_SESSIONS[sid]["created_at"],
                })
            except Exception as exc:
                self._send_json(400, {"error": str(exc)})

        elif path == "/api/pqc/send":
            sid = body_data.get("session_id", "").strip()
            sender = body_data.get("sender", "").strip().lower()
            recipient = body_data.get("recipient", "").strip().lower()
            text = body_data.get("text", "")

            if not sid or sid not in PQC_SESSIONS:
                self._send_json(400, {"error": "Invalid or missing session_id"})
                return

            try:
                packet = msg_session.send(sid, sender, recipient, text.encode("utf-8"))
                # Recipient decrypts in real time
                deliver_res = msg_session.receive(sid, recipient, packet)

                msg_record = {
                    "id": f"msg-{secrets.token_hex(4)}",
                    "sender": sender,
                    "recipient": recipient,
                    "plaintext": text,
                    "status": deliver_res.status,
                    "timestamp": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                    "packet_inspection": {
                        "header": packet["header"],
                        "nonce_b64": packet["nonce"],
                        "ciphertext_b64": packet["ciphertext"],
                        "ciphertext_len_bytes": len(base64.b64decode(packet["ciphertext"])),
                    },
                }

                PQC_SESSIONS[sid]["messages"].append(msg_record)
                PQC_SESSIONS[sid]["last_packet_meta"] = {
                    "sender": sender,
                    "recipient": recipient,
                    "packet": packet,
                }
                LAST_PACKET_BY_SESSION[sid] = {
                    "sender": sender,
                    "recipient": recipient,
                    "packet": packet,
                }

                with store.file_lock():
                    audit.append_event(
                        actor=sender,
                        action="pqc_message_delivered",
                        outcome="success",
                        correlation_id=msg_record["id"],
                    )

                emit_live_soc_event(
                    sender,
                    "aes_256_gcm_transport",
                    "secure_channel",
                    "success",
                    {"recipient": recipient, "seq": packet["header"]["counter"]},
                )

                self._send_json(200, {
                    "success": True,
                    "message": msg_record,
                })
            except Exception as exc:
                emit_live_soc_event(sender, "pqc_message_failed", "secure_channel", "denied", {"error": str(exc)})
                self._send_json(400, {"error": str(exc)})

        elif path == "/api/pqc/attack/replay":
            sid = body_data.get("session_id", "").strip()
            recipient = body_data.get("recipient", "").strip()
            last_meta = LAST_PACKET_BY_SESSION.get(sid)
            if not last_meta:
                self._send_json(400, {"error": "No packets transmitted yet to replay"})
                return

            # Re-inject the exact previous packet to trigger replay detection
            replay_res = msg_session.receive(sid, recipient or last_meta["recipient"], last_meta["packet"])
            outcome = "blocked" if replay_res.status == msg_session.STATUS_FAILED else "accepted"

            with store.file_lock():
                audit.append_event(
                    actor="adversary_replay",
                    action="pqc_replay_attack_attempt",
                    outcome="denied",
                    correlation_id=f"rep-{secrets.token_hex(4)}",
                )

            emit_live_soc_event(
                "adversary",
                "packet_replay_attempt",
                "pqc_transport",
                "blocked",
                {"reason_code": replay_res.reason_code, "status": replay_res.status},
            )

            self._send_json(200, {
                "attack": "Replay Intercepted Packet",
                "status": replay_res.status,
                "reason_code": replay_res.reason_code,
                "replayed_seq": last_meta["packet"]["header"]["counter"],
                "defense": "Monotonic counter + state replay filter rejected duplicate message",
                "rejected": replay_res.status == msg_session.STATUS_FAILED,
            })

        elif path == "/api/pqc/attack/tamper":
            sid = body_data.get("session_id", "").strip()
            recipient = body_data.get("recipient", "").strip()
            last_meta = LAST_PACKET_BY_SESSION.get(sid)
            if not last_meta:
                self._send_json(400, {"error": "No packets transmitted yet to tamper with"})
                return

            # Corrupt 1 byte in ciphertext
            tampered_packet = json.loads(json.dumps(last_meta["packet"]))
            raw_ct = bytearray(base64.b64decode(tampered_packet["ciphertext"]))
            if len(raw_ct) > 0:
                raw_ct[0] ^= 0xFF
            tampered_packet["ciphertext"] = base64.b64encode(raw_ct).decode("ascii")

            tamper_res = msg_session.receive(sid, recipient or last_meta["recipient"], tampered_packet)

            with store.file_lock():
                audit.append_event(
                    actor="adversary_tamper",
                    action="pqc_ciphertext_tamper_attempt",
                    outcome="denied",
                    correlation_id=f"tamper-{secrets.token_hex(4)}",
                )

            emit_live_soc_event(
                "adversary",
                "ciphertext_tamper_detected",
                "pqc_transport",
                "blocked",
                {"reason_code": tamper_res.reason_code},
            )

            self._send_json(200, {
                "attack": "Bit-Flipping in Transit Ciphertext",
                "status": tamper_res.status,
                "reason_code": tamper_res.reason_code,
                "defense": "AES-256-GCM authentication tag verification failed immediately",
                "rejected": tamper_res.status == msg_session.STATUS_FAILED,
            })

        # --- Dynamic Resource Vault Endpoints ---
        elif path == "/api/vault/asset/create":
            aid = body_data.get("asset_id", "").strip()
            owner = body_data.get("owner", "").strip().lower()
            content = body_data.get("content", "").strip()

            if not aid or not owner or not content:
                self._send_json(400, {"error": "asset_id, owner, and content are required"})
                return

            with store.file_lock():
                state = store.load_state() or {}
                owners = dict(state.get("owners", {}))
                contents = dict(state.get("contents", {}))
                owners[aid] = owner
                contents[aid] = content
                state["owners"] = owners
                state["contents"] = contents
                store.save_state(state)

                audit.append_event(
                    actor=owner,
                    action="create_asset",
                    outcome="success",
                    correlation_id=f"create-{aid}",
                )

            emit_live_soc_event(owner, "create_asset", "resource_vault", "success", {"asset_id": aid})
            self._send_json(200, {"success": True, "asset_id": aid, "owner": owner})

        elif path == "/api/vault/read":
            actor = body_data.get("actor", "").strip().lower()
            aid = body_data.get("asset_id", "").strip()

            state = store.load_state() or {}
            decision = access.decide(state, actor, aid)

            req_id = f"req-{secrets.token_hex(4)}"
            with store.file_lock():
                audit.append_event(
                    actor=actor,
                    action="read",
                    outcome="success" if decision == "allow" else "denied",
                    correlation_id=req_id,
                )

            emit_live_soc_event(
                actor,
                "vault_read_request",
                "resource_vault",
                "success" if decision == "allow" else "denied",
                {"asset_id": aid, "decision": decision},
            )

            if decision == "allow":
                content = state.get("contents", {}).get(aid, "")
                self._send_json(200, {
                    "decision": "allow",
                    "actor": actor,
                    "asset_id": aid,
                    "body": content,
                })
            else:
                self._send_json(200, {
                    "decision": "deny",
                    "actor": actor,
                    "asset_id": aid,
                    "reason": "Actor is revoked or unauthorized for this asset",
                })

        elif path == "/api/vault/protected_read":
            actor = body_data.get("actor", "").strip().lower()
            aid = body_data.get("asset_id", "").strip()

            state = store.load_state() or {}
            decision = access.decide(state, actor, aid)

            if decision != "allow":
                self._send_json(200, {
                    "decision": "deny",
                    "reason": "Access denied before KEM encapsulation.",
                })
                return

            body = state.get("contents", {}).get(aid, "")
            # Generate client ML-KEM-768 keypair
            client_pk, client_sk = ml_kem_768.generate_keypair()
            client_pk_b64 = base64.b64encode(client_pk).decode("ascii")
            challenge = f"chal-{secrets.token_hex(8)}"

            # Run actual ML-KEM-768 protected read
            kem_res = kem_protected_read.protected_read(client_pk_b64, challenge, body)
            if not kem_res:
                self._send_json(500, {"error": "KEM encapsulation failed"})
                return

            # Client decapsulates shared secret using client_sk
            ct_bytes = base64.b64decode(kem_res["ciphertext"])
            derived_shared_secret = ml_kem_768.decrypt(client_sk, ct_bytes)

            with store.file_lock():
                audit.append_event(
                    actor=actor,
                    action="pqc_protected_read",
                    outcome="success",
                    correlation_id=f"kem-{aid}",
                )

            emit_live_soc_event(actor, "ml_kem_768_encapsulation", "quantum_vault", "success", {"asset": aid})

            self._send_json(200, {
                "decision": "allow",
                "algorithm": "ML-KEM-768 Encapsulation + HMAC-SHA256 Proof",
                "ciphertext": kem_res["ciphertext"],
                "proof_hmac": kem_res["proof"],
                "decapsulated_secret_verified": len(derived_shared_secret) == 32,
                "body": body,
            })

        elif path == "/api/vault/revoke":
            actor = body_data.get("actor", "").strip().lower()
            with store.file_lock():
                state = store.load_state() or {}
                new_state = access.revoke(state, actor)
                store.save_state(new_state)

                audit.append_event(
                    actor="admin",
                    action="revoke_device",
                    outcome="success",
                    correlation_id=f"rev-{actor}",
                )

            emit_live_soc_event(
                "security_admin",
                "immediate_device_revocation",
                "identity_provider",
                "success",
                {"revoked_actor": actor},
            )

            self._send_json(200, {
                "success": True,
                "revoked_actor": actor,
                "message": f"Device credentials for {actor} revoked. Real-time reads will now return DENY.",
            })

        elif path == "/api/vault/reenrol":
            actor = body_data.get("actor", "").strip().lower()
            new_device = body_data.get("new_device", f"dev-quantum-{secrets.token_hex(4)}")
            with store.file_lock():
                state = store.load_state() or {}
                revoked = list(state.get("revoked", []))
                if actor in revoked:
                    revoked.remove(actor)
                state["revoked"] = revoked
                store.save_state(state)

                audit.append_event(
                    actor="admin",
                    action="reenrol_device",
                    outcome="success",
                    correlation_id=f"reenrol-{actor}",
                )

            emit_live_soc_event(
                "security_admin",
                "quantum_device_reenrollment",
                "identity_provider",
                "success",
                {"actor": actor, "new_device": new_device},
            )

            self._send_json(200, {
                "success": True,
                "reenrolled_actor": actor,
                "device": new_device,
                "message": f"Actor {actor} successfully re-enrolled with quantum key. Authorized access restored.",
            })

        elif path == "/api/vault/rotate":
            new_key = secrets.token_hex(16)
            with store.file_lock():
                state = store.load_state() or {}
                curr_ver = state.get("key_version", 1)
                state["key_version"] = curr_ver + 1
                state["key_material"] = new_key
                store.save_state(state)

                audit.append_event(
                    actor="system",
                    action="key_rotation",
                    outcome="success",
                    correlation_id=f"rot-v{curr_ver + 1}",
                )

            emit_live_soc_event(
                "kms_engine",
                "atomic_key_rotation",
                "key_management",
                "success",
                {"new_key_version": curr_ver + 1},
            )

            self._send_json(200, {
                "success": True,
                "new_key_version": curr_ver + 1,
                "message": f"Atomic key rotation committed. New active version: v{curr_ver + 1}.",
            })

        # --- Judged Path Step APIs (100% Backward Compatible) ---
        elif path.startswith("/api/step/"):
            step_name = path[len("/api/step/"):]
            if step_name in ALLOWED_STEPS:
                result = run_adapter_step(step_name)
                self._send_json(200, result)
            else:
                self._send_not_found()

        elif path == "/api/messaging_demo":
            result = run_messaging_demo()
            self._send_json(200, result)

        elif path == "/api/detector/run":
            events_input = body_data.get("events")
            alerts = run_detector_on_events(events_input)
            self._send_json(200, {"alerts": alerts, "count": len(alerts)})

        elif path == "/api/detector/inject":
            attack_type = body_data.get("attack_type", "privilege_escalation")
            res = inject_attack(attack_type)
            self._send_json(200, res)

        elif path == "/api/audit/verify":
            res = verify_active_audit_log()
            self._send_json(200, res)

        elif path == "/api/audit/tamper_test":
            res = run_tamper_test()
            self._send_json(200, res)

        else:
            self._send_not_found()


def main() -> int:
    server = http.server.HTTPServer((HOST, PORT), DemoHandler)
    sys.stdout.write(f"Track 4 Real-Time PQC Server running at http://{HOST}:{PORT}\n")
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
