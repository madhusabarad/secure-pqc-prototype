"""Integration tests for the real-time PQC frontend APIs."""

import json
import threading
import time
import urllib.request
import pytest

from frontend import server

_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


@pytest.fixture(scope="module")
def realtime_server():
    server._ensure_identities_registered()
    httpd = server.http.server.HTTPServer(("127.0.0.1", 0), server.DemoHandler)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.3)
    yield f"http://127.0.0.1:{port}"
    httpd.shutdown()
    httpd.server_close()


def _get(url: str) -> dict | str:
    req = urllib.request.Request(url)
    with _opener.open(req, timeout=10) as resp:
        content_type = resp.headers.get("Content-Type", "")
        data = resp.read().decode("utf-8")
        if "application/json" in content_type:
            return json.loads(data)
        return data


def _post(url: str, payload: dict | None = None) -> dict:
    data_bytes = json.dumps(payload or {}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data_bytes,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with _opener.open(req, timeout=15) as resp:
        return json.loads(resp.read().decode("utf-8"))


def test_realtime_pqc_chat_flow(realtime_server):
    # 1. Identities
    identities_res = _get(realtime_server + "/api/pqc/identities")
    assert "identities" in identities_res
    users = [u["user"] for u in identities_res["identities"]]
    assert "alice" in users
    assert "bob" in users

    # 2. Handshake between alice and bob
    hs_res = _post(realtime_server + "/api/pqc/handshake", {"initiator": "alice", "responder": "bob"})
    assert hs_res.get("success") is True
    sid = hs_res["session_id"]
    assert len(sid) > 0

    # 3. Send message
    send_res = _post(realtime_server + "/api/pqc/send", {
        "session_id": sid,
        "sender": "alice",
        "recipient": "bob",
        "text": "Quantum-safe greetings Bob!",
    })
    assert send_res.get("success") is True
    assert send_res["message"]["status"].upper() == "DELIVERED"
    assert "packet_inspection" in send_res["message"]

    # 4. Fetch messages
    msg_res = _get(realtime_server + f"/api/pqc/messages?session_id={sid}")
    assert len(msg_res.get("messages", [])) >= 1
    assert msg_res["messages"][-1]["plaintext"] == "Quantum-safe greetings Bob!"

    # 5. Test Replay attack defense
    replay_res = _post(realtime_server + "/api/pqc/attack/replay", {
        "session_id": sid,
        "recipient": "bob",
    })
    assert replay_res.get("rejected") is True
    assert replay_res.get("status").upper() == "FAILED"

    # 6. Test Tamper attack defense
    tamper_res = _post(realtime_server + "/api/pqc/attack/tamper", {
        "session_id": sid,
        "recipient": "bob",
    })
    assert tamper_res.get("rejected") is True
    assert tamper_res.get("status").upper() == "FAILED"


def test_dynamic_vault_and_pqc_protected_read(realtime_server):
    # 1. Create a custom dynamic asset
    create_res = _post(realtime_server + "/api/vault/asset/create", {
        "asset_id": "doc-top-secret-omega",
        "owner": "alice",
        "content": "Secret missile coordinates and telemetry parameters",
    })
    assert create_res.get("success") is True

    # 2. Authorized read by owner -> allow
    read_res = _post(realtime_server + "/api/vault/read", {
        "actor": "alice",
        "asset_id": "doc-top-secret-omega",
    })
    assert read_res.get("decision") == "allow"
    assert "Secret missile coordinates" in read_res.get("body", "")

    # 3. Unauthorized read by peer -> deny
    peer_read_res = _post(realtime_server + "/api/vault/read", {
        "actor": "bob",
        "asset_id": "doc-top-secret-omega",
    })
    assert peer_read_res.get("decision") == "deny"

    # 4. Post-Quantum Protected Read via ML-KEM-768
    kem_read_res = _post(realtime_server + "/api/vault/protected_read", {
        "actor": "alice",
        "asset_id": "doc-top-secret-omega",
    })
    assert kem_read_res.get("decision") == "allow"
    assert "ML-KEM-768" in kem_read_res.get("algorithm", "")
    assert kem_read_res.get("decapsulated_secret_verified") is True

    # 5. Revoke actor device -> immediate denial
    rev_res = _post(realtime_server + "/api/vault/revoke", {"actor": "alice"})
    assert rev_res.get("success") is True

    # Subsequent read by alice is now immediately denied
    post_rev_read = _post(realtime_server + "/api/vault/read", {
        "actor": "alice",
        "asset_id": "doc-top-secret-omega",
    })
    assert post_rev_read.get("decision") == "deny"

    # 6. Re-enroll actor device -> access restored
    reenrol_res = _post(realtime_server + "/api/vault/reenrol", {
        "actor": "alice",
        "new_device": "dev-quantum-yubikey-5c",
    })
    assert reenrol_res.get("success") is True

    post_reenrol_read = _post(realtime_server + "/api/vault/read", {
        "actor": "alice",
        "asset_id": "doc-top-secret-omega",
    })
    assert post_reenrol_read.get("decision") == "allow"


def test_soc_live_feed_and_audit_ledger(realtime_server):
    # 1. Trigger SOC threat injection
    threat_res = _post(realtime_server + "/api/detector/inject", {
        "attack_type": "privilege_escalation"
    })
    assert threat_res.get("detected") is True
    assert len(threat_res.get("alerts", [])) > 0

    # 2. Live feed contains events
    feed_res = _get(realtime_server + "/api/soc/live_feed")
    assert "stream" in feed_res
    assert len(feed_res["stream"]) > 0

    # 3. Audit ledger verification
    audit_res = _get(realtime_server + "/api/audit/entries")
    assert "entries" in audit_res
    assert len(audit_res["entries"]) > 0

    # Verify cryptographic integrity
    verify_res = _post(realtime_server + "/api/audit/verify", {})
    assert verify_res.get("valid") is True
