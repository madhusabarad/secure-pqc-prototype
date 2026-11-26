"""End-to-end prototype demonstration for Track 4 access control, protected_read, and Part A messaging."""

from __future__ import annotations

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

from pqcrypto.kem.ml_kem_768 import decrypt as ml_kem_decrypt, generate_keypair as ml_kem_generate_keypair

from messaging.demo_part_a import run_demo as run_part_a_demo

REPO_ROOT = Path(__file__).parent.resolve()
ENTRY_SCRIPT = REPO_ROOT / "track4_service.py"


def _call_adapter(state_dir: Path, **request: object) -> dict:
    """Invoke track4_service.py with one JSON request in an isolated state directory."""
    env = os.environ.copy()
    state_str = str(state_dir)
    for var in ("TRACK4_STATE_DIR", "TMPDIR", "TEMP", "TMP"):
        env[var] = state_str

    proc = subprocess.run(
        [sys.executable, "-B", str(ENTRY_SCRIPT)],
        cwd=REPO_ROOT,
        env=env,
        input=json.dumps(request).encode("utf-8"),
        capture_output=True,
        timeout=10.0,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"track4_service failed with exit code {proc.returncode}")
    return json.loads(proc.stdout.decode("utf-8"))


def _run_track4_flow() -> None:
    """Demonstrate Track 4 setup, read, revoke, audit, and unaffected peer isolation."""
    print("=== 1. Track 4 Access Control & Audit Flow ===")
    with tempfile.TemporaryDirectory(prefix="t4-demo-flow-") as tmp_dir:
        state_dir = Path(tmp_dir)
        owner_body = "record-alpha-content"
        peer_body = "record-beta-content"
        setup_res = _call_adapter(
            state_dir,
            op="setup",
            owners={"asset-alpha": "alice", "asset-beta": "bob"},
            contents={"asset-alpha": owner_body, "asset-beta": peer_body},
            disabled=[],
            key_material=secrets.token_hex(16),
        )
        assert setup_res.get("ready") is True
        print(f"Setup: ready={setup_res['ready']}")

        req_allow = "req-owner-allow"
        read_allow = _call_adapter(
            state_dir,
            op="read",
            actor="alice",
            asset="asset-alpha",
            request_id=req_allow,
        )
        assert read_allow.get("decision") == "allow"
        assert read_allow.get("body") == owner_body
        print(f"Owner read (before revoke): decision={read_allow['decision']}, body_present={bool(read_allow.get('body'))}")

        revoke_res = _call_adapter(state_dir, op="revoke", actor="alice", request_id="req-revoke-alice")
        assert isinstance(revoke_res, dict)
        print("Revoke owner (alice): completed")

        req_deny = "req-owner-deny"
        read_deny = _call_adapter(
            state_dir,
            op="read",
            actor="alice",
            asset="asset-alpha",
            request_id=req_deny,
        )
        assert read_deny.get("decision") == "deny"
        assert "body" not in read_deny or not read_deny["body"]
        print(f"Owner read (after revoke): decision={read_deny['decision']}, body_present={'body' in read_deny}")

        audit_res = _call_adapter(state_dir, op="audit", request_id=req_deny)
        assert audit_res.get("request_id") == req_deny
        assert audit_res.get("decision") == "deny"
        print(
            f"Audit lookup (request_id={audit_res['request_id']}): "
            f"decision={audit_res['decision']} (confirms revoked owner denial)"
        )

        peer_read = _call_adapter(
            state_dir,
            op="read",
            actor="bob",
            asset="asset-beta",
            request_id="req-peer-allow",
        )
        assert peer_read.get("decision") == "allow"
        assert peer_read.get("body") == peer_body
        print(f"Second owner read (bob): decision={peer_read['decision']}, body_present={bool(peer_read.get('body'))}")


def _run_protected_read_flow() -> None:
    """Demonstrate protected_read via track4_service with ML-KEM-768 and revocation."""
    print("\n=== 2. Protected Read (ML-KEM-768) ===")
    with tempfile.TemporaryDirectory(prefix="t4-demo-prot-") as tmp_dir:
        state_dir = Path(tmp_dir)
        body = "protected-asset-payload"
        setup_res = _call_adapter(
            state_dir,
            op="setup",
            owners={"asset-prot": "alice"},
            contents={"asset-prot": body},
            disabled=[],
            key_material=secrets.token_hex(16),
        )
        assert setup_res.get("ready") is True

        pk, sk = ml_kem_generate_keypair()
        pk_b64 = base64.b64encode(pk).decode("ascii")
        challenge = "demo-challenge-" + secrets.token_hex(8)

        allow_res = _call_adapter(
            state_dir,
            op="protected_read",
            actor="alice",
            asset="asset-prot",
            challenge=challenge,
            public_key=pk_b64,
            request_id="req-prot-allow",
        )
        assert "ciphertext" in allow_res and "proof" in allow_res
        shared_secret = ml_kem_decrypt(sk, base64.b64decode(allow_res["ciphertext"], validate=True))
        expected_proof = hmac.new(shared_secret, (challenge + body).encode("utf-8"), hashlib.sha256).hexdigest()
        assert hmac.compare_digest(allow_res["proof"], expected_proof)
        print("Allowed owner protected_read: ciphertext and proof returned (ML-KEM-768 + HMAC verified)")

        _call_adapter(state_dir, op="revoke", actor="alice", request_id="req-prot-revoke")
        deny_res = _call_adapter(
            state_dir,
            op="protected_read",
            actor="alice",
            asset="asset-prot",
            challenge="demo-challenge-" + secrets.token_hex(8),
            public_key=pk_b64,
            request_id="req-prot-deny",
        )
        assert deny_res == {"decision": "deny"}
        assert "ciphertext" not in deny_res
        print(f"Revoked owner protected_read: decision={deny_res['decision']}, ciphertext_present={'ciphertext' in deny_res}")


def main() -> int:
    _run_track4_flow()
    _run_protected_read_flow()
    print("\n=== 3. Part A Secure Messaging Scenarios ===")
    run_part_a_demo()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
