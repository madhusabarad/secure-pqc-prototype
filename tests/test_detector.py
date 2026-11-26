"""Comprehensive pytest test suite for Person D detector, time ordering, and evaluator."""

from __future__ import annotations

from datetime import UTC, datetime

import detector
from detector.evaluator import evaluate_detector
from detector.time_order import (
    correct_event_time,
    normalize_and_order_events,
)
from simdata.generator import generate_events, load_approvals

# ==============================================================================
# RULE 1: PRIVILEGE TESTS
# ==============================================================================


def test_unapproved_privilege_change_is_detected():
    """Unapproved privilege change must trigger PRIVILEGE_CHANGE_WITHOUT_APPROVAL alert."""
    event = {
        "event_id": "evt_priv_unapproved",
        "event_time_utc": "2026-11-26T12:00:00Z",
        "actor": "user07",
        "source_service": "portal",
        "target_service": "auth",
        "action": "role_change",
        "role_before": "user",
        "role_after": "admin",
        "approval_id": None,
        "source_clock_offset_ms": 0,
    }

    alerts = detector.run([event])
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["rule"] == "PRIVILEGE_CHANGE_WITHOUT_APPROVAL"
    assert alert["actor"] == "user07"
    assert alert["event_ids"] == ["evt_priv_unapproved"]
    assert "without required approval_id" in alert["reason"]


def test_approved_privilege_change_is_not_detected():
    """Legitimate approved privilege change must NOT trigger an alert."""
    approvals = load_approvals()
    assert len(approvals) > 0
    valid_approval = approvals[0]

    event = {
        "event_id": "evt_priv_approved",
        "event_time_utc": "2026-11-26T12:00:00Z",
        "actor": valid_approval["actor"],
        "source_service": "portal",
        "target_service": "auth",
        "action": valid_approval["approved_action"],
        "role_before": valid_approval["role_before"],
        "role_after": valid_approval["role_after"],
        "approval_id": valid_approval["approval_id"],
        "source_clock_offset_ms": 0,
    }

    alerts = detector.run([event])
    assert len(alerts) == 0


def test_invalid_approval_id_is_detected():
    """Privilege change referencing invalid approval ID must trigger alert."""
    event = {
        "event_id": "evt_priv_fake",
        "event_time_utc": "2026-11-26T12:00:00Z",
        "actor": "user14",
        "source_service": "portal",
        "target_service": "auth",
        "action": "role_change",
        "role_before": "user",
        "role_after": "admin",
        "approval_id": "NON_EXISTENT_APR_999",
        "source_clock_offset_ms": 0,
    }

    alerts = detector.run([event])
    assert len(alerts) == 1
    assert alerts[0]["rule"] == "PRIVILEGE_CHANGE_WITHOUT_APPROVAL"
    assert "unknown or invalid approval_id" in alerts[0]["reason"]


# ==============================================================================
# RULE 2: LATERAL MOVEMENT TESTS
# ==============================================================================


def test_first_ever_service_path_is_detected():
    """An actor communicating along a service path never previously observed triggers alert."""
    # user08 normal paths: portal->auth, portal->database, orders->payments
    # Injected new path: payments -> reports
    event = {
        "event_id": "evt_lateral_01",
        "event_time_utc": "2026-11-26T12:00:00Z",
        "actor": "user08",
        "source_service": "payments",
        "target_service": "reports",
        "action": "service_access",
        "source_clock_offset_ms": 0,
    }

    alerts = detector.run([event])
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["rule"] == "LATERAL_MOVEMENT_FIRST_PATH"
    assert alert["actor"] == "user08"
    assert alert["source_service"] == "payments"
    assert alert["target_service"] == "reports"
    assert "Lateral movement detected" in alert["reason"]


def test_known_service_path_is_not_incorrectly_detected():
    """An actor communicating along their established normal path must NOT trigger an alert."""
    # user08 normal path includes portal -> database
    event = {
        "event_id": "evt_normal_path",
        "event_time_utc": "2026-11-26T12:00:00Z",
        "actor": "user08",
        "source_service": "portal",
        "target_service": "database",
        "action": "database_read",
        "source_clock_offset_ms": 0,
    }

    alerts = detector.run([event])
    assert len(alerts) == 0


# ==============================================================================
# RULE 3: DATA ACCESS SPIKE TESTS
# ==============================================================================


def test_data_access_spike_is_detected():
    """A sudden high burst of data reads for an actor must trigger DATA_ACCESS_SPIKE."""
    # user12 normal baseline is ~8 reads. Inject burst of 30 reads within 30 seconds.
    burst_events = [
        {
            "event_id": f"evt_spike_{i:03d}",
            "event_time_utc": f"2026-11-26T12:00:{i % 30:02d}Z",
            "actor": "user12",
            "source_service": "portal",
            "target_service": "database",
            "action": "database_read",
            "source_clock_offset_ms": 0,
        }
        for i in range(30)
    ]

    alerts = detector.run(burst_events)
    spike_alerts = [a for a in alerts if a["rule"] == "DATA_ACCESS_SPIKE"]
    assert len(spike_alerts) == 1
    assert spike_alerts[0]["actor"] == "user12"
    assert len(spike_alerts[0]["event_ids"]) >= 24
    assert "exceeding baseline" in spike_alerts[0]["reason"]


def test_normal_data_activity_is_not_incorrectly_detected():
    """Normal low volume data access matching baseline must NOT trigger alert."""
    # user12 performing 3 normal reads
    normal_events = [
        {
            "event_id": f"evt_norm_{i}",
            "event_time_utc": f"2026-11-26T12:00:{i * 10:02d}Z",
            "actor": "user12",
            "source_service": "portal",
            "target_service": "database",
            "action": "database_read",
            "source_clock_offset_ms": 0,
        }
        for i in range(3)
    ]

    alerts = detector.run(normal_events)
    spike_alerts = [a for a in alerts if a["rule"] == "DATA_ACCESS_SPIKE"]
    assert len(spike_alerts) == 0


# ==============================================================================
# TIME ORDERING AND SKEW TESTS
# ==============================================================================


def test_positive_clock_skew():
    """Test handling of positive source clock skew (+60,000ms = 60s ahead of UTC)."""
    event = {
        "event_id": "evt_skew_pos",
        "event_time_utc": "2026-11-26T12:01:00Z",
        "source_clock_offset_ms": 60000,
        "received_time_utc": "2026-11-26T12:00:05Z",
    }
    corr_time, _, _ = correct_event_time(event)
    assert corr_time == datetime(2026, 11, 26, 12, 0, 0, tzinfo=UTC)


def test_negative_clock_skew():
    """Test handling of negative source clock skew (-60,000ms = 60s behind UTC)."""
    event = {
        "event_id": "evt_skew_neg",
        "event_time_utc": "2026-11-26T11:59:00Z",
        "source_clock_offset_ms": -60000,
        "received_time_utc": "2026-11-26T12:00:05Z",
    }
    corr_time, _, _ = correct_event_time(event)
    assert corr_time == datetime(2026, 11, 26, 12, 0, 0, tzinfo=UTC)


def test_late_events():
    """Test handling of late events up to 5 minutes (300 seconds) after occurrence."""
    event = {
        "event_id": "evt_late",
        "event_time_utc": "2026-11-26T12:00:00Z",
        "source_clock_offset_ms": 0,
        "received_time_utc": "2026-11-26T12:04:30Z",
    }
    _, _recv_time, delay_sec = correct_event_time(event)
    assert delay_sec == 270.0
    assert delay_sec <= 300.0


def test_reordered_events():
    """Test sorting of events received out-of-order restores chronological sequence."""
    e1 = {
        "event_id": "e_first",
        "event_time_utc": "2026-11-26T12:00:00Z",
        "source_clock_offset_ms": 0,
        "received_time_utc": "2026-11-26T12:00:10Z",
    }
    e2 = {
        "event_id": "e_second",
        "event_time_utc": "2026-11-26T12:00:05Z",
        "source_clock_offset_ms": 0,
        "received_time_utc": "2026-11-26T12:00:06Z",
    }
    # Pass in reverse arrival order
    ordered = normalize_and_order_events([e2, e1])
    assert ordered[0]["event_id"] == "e_first"
    assert ordered[1]["event_id"] == "e_second"


def test_uncertain_ordering():
    """Test detection of uncertain ordering for closely timed events involving same actor."""
    e1 = {
        "event_id": "u1",
        "actor": "user05",
        "source_service": "portal",
        "target_service": "auth",
        "event_time_utc": "2026-11-26T12:00:00.500Z",
        "source_clock_offset_ms": 0,
    }
    e2 = {
        "event_id": "u2",
        "actor": "user05",
        "source_service": "portal",
        "target_service": "auth",
        "event_time_utc": "2026-11-26T12:00:01.000Z",
        "source_clock_offset_ms": 0,
    }
    ordered = normalize_and_order_events([e1, e2])
    # Both events within 0.5s of each other must have order_uncertain = True
    assert ordered[0]["order_uncertain"] is True
    assert ordered[1]["order_uncertain"] is True


# ==============================================================================
# ALERT STRUCTURE TESTS
# ==============================================================================


def test_alert_contains_actor():
    """Alert must contain actor field."""
    event = {
        "event_id": "evt_alert_test",
        "event_time_utc": "2026-11-26T12:00:00Z",
        "actor": "user07",
        "source_service": "portal",
        "target_service": "auth",
        "action": "role_change",
        "role_before": "user",
        "role_after": "admin",
        "approval_id": None,
    }
    alerts = detector.run([event])
    assert len(alerts) > 0
    assert alerts[0]["actor"] == "user07"


def test_alert_contains_rule():
    """Alert must contain rule field."""
    event = {
        "event_id": "evt_alert_test",
        "event_time_utc": "2026-11-26T12:00:00Z",
        "actor": "user07",
        "source_service": "portal",
        "target_service": "auth",
        "action": "role_change",
        "role_before": "user",
        "role_after": "admin",
        "approval_id": None,
    }
    alerts = detector.run([event])
    assert len(alerts) > 0
    assert alerts[0]["rule"] == "PRIVILEGE_CHANGE_WITHOUT_APPROVAL"


def test_alert_contains_reason():
    """Alert must contain explanatory reason."""
    event = {
        "event_id": "evt_alert_test",
        "event_time_utc": "2026-11-26T12:00:00Z",
        "actor": "user07",
        "source_service": "portal",
        "target_service": "auth",
        "action": "role_change",
        "role_before": "user",
        "role_after": "admin",
        "approval_id": None,
    }
    alerts = detector.run([event])
    assert len(alerts) > 0
    assert "reason" in alerts[0]
    assert len(alerts[0]["reason"]) > 10


def test_alert_contains_event_ids():
    """Alert must contain list of triggering event_ids."""
    event = {
        "event_id": "evt_alert_test_99",
        "event_time_utc": "2026-11-26T12:00:00Z",
        "actor": "user07",
        "source_service": "portal",
        "target_service": "auth",
        "action": "role_change",
        "role_before": "user",
        "role_after": "admin",
        "approval_id": None,
    }
    alerts = detector.run([event])
    assert len(alerts) > 0
    assert "event_ids" in alerts[0]
    assert "evt_alert_test_99" in alerts[0]["event_ids"]


# ==============================================================================
# GENERATOR & EVALUATOR TESTS
# ==============================================================================


def test_generator_is_deterministic():
    """Calling generate_events with identical seed must return identical data."""
    evts1, gt1 = generate_events(seed=123, count=200, shuffle=False)
    evts2, gt2 = generate_events(seed=123, count=200, shuffle=False)

    assert len(evts1) == len(evts2)
    assert len(gt1) == len(gt2)
    assert evts1 == evts2
    assert gt1 == gt2


def test_evaluator_calculates_all_three_metrics():
    """Evaluator must calculate F1 score, false alerts per 1000, and median time to alert."""
    results = evaluate_detector(seed=42, count=500)

    assert "f1_score" in results
    assert "false_alerts_per_1000" in results
    assert "median_time_to_alert_seconds" in results

    assert isinstance(results["f1_score"], float)
    assert isinstance(results["false_alerts_per_1000"], float)
    assert isinstance(results["median_time_to_alert_seconds"], float)

    # Valid metric ranges
    assert 0.0 <= results["f1_score"] <= 1.0
    assert results["false_alerts_per_1000"] >= 0.0
    assert results["median_time_to_alert_seconds"] >= 0.0

    # Ensure coverage statistics exist
    assert "PRIVILEGE_WITHOUT_APPROVAL" in results["coverage"]
    assert "LATERAL_MOVEMENT" in results["coverage"]
    assert "DATA_ACCESS_SPIKE" in results["coverage"]
