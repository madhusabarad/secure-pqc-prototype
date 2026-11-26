"""Main security detector module providing detector.run(events) interface."""

from __future__ import annotations

from typing import Any

from detector.rules import (
    DataAccessSpikeRule,
    LateralMovementRule,
    PrivilegeRule,
)
from detector.time_order import normalize_and_order_events

REQUIRED_EVENT_FIELDS = {
    "event_id",
    "event_time_utc",
    "actor",
    "source_service",
    "target_service",
    "action",
}


class SecurityDetector:
    """Security Detector implementing deterministic rules and statistical anomaly detection."""

    def __init__(
        self,
        approvals: list[dict[str, Any]] | None = None,
        known_paths: dict[str, list[tuple[str, str]] | set[tuple[str, str]]] | None = None,
        baseline_means: dict[str, int | float] | None = None,
    ) -> None:
        self.privilege_rule = PrivilegeRule(approvals=approvals)
        self.lateral_rule = LateralMovementRule(known_paths=known_paths)
        self.spike_rule = DataAccessSpikeRule(baseline_means=baseline_means)

    def validate_event(self, event: Any) -> bool:
        """Validate event schema; return False if malformed."""
        if not isinstance(event, dict):
            return False
        # Event must contain at minimum an event_id and actor
        return bool(event.get("event_id") and event.get("actor"))

    def run(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Run security detector against a batch of security/audit events.

        Steps:
        1. Validates input events (skipping malformed events without crashing).
        2. Applies source clock skew correction and deterministic time ordering.
        3. Applies Rule 1: PRIVILEGE_CHANGE_WITHOUT_APPROVAL.
        4. Applies Rule 2: LATERAL_MOVEMENT_FIRST_PATH.
        5. Applies Rule 3: DATA_ACCESS_SPIKE.
        6. Combines and returns structured alerts.
        """
        if not events:
            return []

        # 1. Validate inputs (malformed events must not crash detector)
        valid_events: list[dict[str, Any]] = []
        for evt in events:
            if self.validate_event(evt):
                valid_events.append(evt)

        if not valid_events:
            return []

        # 2. Time ordering and clock skew normalization
        ordered_events = normalize_and_order_events(valid_events)

        alerts: list[dict[str, Any]] = []

        # 3 & 4. Per-event rule evaluation (Privilege and Lateral Movement)
        for evt in ordered_events:
            # Rule 1
            priv_alert = self.privilege_rule.evaluate(evt)
            if priv_alert:
                alerts.append(priv_alert)

            # Rule 2
            lat_alert = self.lateral_rule.evaluate(evt)
            if lat_alert:
                alerts.append(lat_alert)

        # 5. Batch statistical evaluation (Data Access Spike)
        spike_alerts = self.spike_rule.evaluate_batch(ordered_events)
        alerts.extend(spike_alerts)

        return alerts


# Module-level default instance for detector.run(events) contract
_default_detector = SecurityDetector()


def run(
    events: list[dict[str, Any]],
    approvals: list[dict[str, Any]] | None = None,
    known_paths: dict[str, list[tuple[str, str]] | set[tuple[str, str]]] | None = None,
    baseline_means: dict[str, int | float] | None = None,
) -> list[dict[str, Any]]:
    """Required public API: detector.run(events).

    Args:
        events: List of event dicts in practice schema.
        approvals: Optional custom approvals list.
        known_paths: Optional custom known paths mapping.
        baseline_means: Optional custom baseline means mapping.

    Returns:
        List of structured alert dictionaries.
    """
    if approvals is not None or known_paths is not None or baseline_means is not None:
        detector = SecurityDetector(
            approvals=approvals,
            known_paths=known_paths,
            baseline_means=baseline_means,
        )
        return detector.run(events)

    # Re-instantiate default detector per call to ensure clean state across test runs
    detector = SecurityDetector()
    return detector.run(events)
