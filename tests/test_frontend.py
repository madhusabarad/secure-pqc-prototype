"""Automated integration tests for the full frontend server."""

from __future__ import annotations

import json
import threading
import time
import urllib.request
import urllib.error
import pytest

from frontend import server

_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


@pytest.fixture(scope="module")
def frontend_server():
    """Start local frontend server in a background daemon thread on an ephemeral port."""
    # Find free port
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


def test_index_page(frontend_server):
    html = _get(frontend_server + "/")
    assert "<!DOCTYPE html>" in html
    assert "Trust, but Verify" in html


def test_lost_device_lifecycle(frontend_server):
    # 1. Setup
    res = _post(frontend_server + "/api/step/setup")
    assert res["label"] == "OK"
    assert res["response"].get("ready") is True

    # 2. Owner read -> allow
    res = _post(frontend_server + "/api/step/owner_read")
    assert res["label"] == "ALLOW"
    assert "Alex confidential" in res["response"].get("body", "")

    # 3. Revoke owner -> ok
    res = _post(frontend_server + "/api/step/revoke_owner")
    assert res["label"] == "OK"

    # 4. Owner read again -> deny
    res = _post(frontend_server + "/api/step/owner_read_again")
    assert res["label"] == "DENY"

    # 5. Audit denied read
    res = _post(frontend_server + "/api/step/audit")
    assert res["label"] == "DENY"
    assert res["response"].get("decision") == "deny"

    # 6. Unaffected peer read -> allow
    res = _post(frontend_server + "/api/step/second_owner_read")
    assert res["label"] == "ALLOW"
    assert "Blair strategic" in res["response"].get("body", "")

    # 7. Re-enroll owner with new quantum device key
    res = _post(frontend_server + "/api/step/reenrol_owner")
    assert res["label"] == "OK"
    assert res["response"].get("reenrolled") is True

    # 8. Post-reenroll read -> allow restored
    res = _post(frontend_server + "/api/step/owner_read_post_reenrol")
    assert res["label"] == "ALLOW"
    assert "Alex confidential" in res["response"].get("body", "")

    # 9. Key rotation -> key_version incremented
    res = _post(frontend_server + "/api/step/rotate_key")
    assert res["label"] == "OK"
    assert res["response"].get("key_version") >= 2


def test_detector_api(frontend_server):
    # Metrics
    metrics = _get(frontend_server + "/api/detector/metrics")
    assert metrics["f1_score"] == 1.0
    assert metrics["false_alerts_per_1000"] == 0.0

    # Sample events
    events_data = _get(frontend_server + "/api/detector/events")
    assert "events" in events_data
    assert len(events_data["events"]) > 0

    # Run detector
    res = _post(frontend_server + "/api/detector/run", {"events": events_data["events"]})
    assert "alerts" in res

    # Inject privilege escalation
    inj_priv = _post(frontend_server + "/api/detector/inject", {"attack_type": "privilege_escalation"})
    assert inj_priv["detected"] is True
    assert inj_priv["alerts"][0]["rule"] == "PRIVILEGE_CHANGE_WITHOUT_APPROVAL"

    # Inject lateral movement
    inj_lat = _post(frontend_server + "/api/detector/inject", {"attack_type": "lateral_movement"})
    assert inj_lat["detected"] is True
    assert inj_lat["alerts"][0]["rule"] == "LATERAL_MOVEMENT_FIRST_PATH"


def test_audit_api(frontend_server):
    # Inspect entries
    entries_data = _get(frontend_server + "/api/audit/entries")
    assert "entries" in entries_data
    assert entries_data["count"] > 0

    # Verify audit log
    verify_res = _post(frontend_server + "/api/audit/verify")
    assert verify_res["valid"] is True
    assert verify_res["entries_count"] > 0

    # Tamper test simulation
    tamper_res = _post(frontend_server + "/api/audit/tamper_test")
    assert tamper_res["tamper_detected"] is True
