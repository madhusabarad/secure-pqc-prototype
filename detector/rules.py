"""Deterministic security rules and simple statistical detection for Person D."""

from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import datetime
from typing import Any, ClassVar

from detector.time_order import parse_iso_timestamp
from simdata.generator import (
    USER_DATA_ACCESS_BASELINE,
    USER_NORMAL_PATHS,
    load_approvals,
)


class PrivilegeRule:
    """RULE 1: PRIVILEGE_CHANGE_WITHOUT_APPROVAL.

    Triggers when a privilege/role change occurs and:
    - required approval is absent
    OR
    - approval ID is invalid
    OR
    - approval does not authorize the action
    Legitimate approved role changes do NOT trigger.
    """

    RULE_NAME = "PRIVILEGE_CHANGE_WITHOUT_APPROVAL"

    def __init__(self, approvals: list[dict[str, Any]] | None = None) -> None:
        if approvals is None:
            approvals = load_approvals()
        # Index valid approvals by approval_id
        self.approvals_by_id: dict[str, dict[str, Any]] = {
            app["approval_id"]: app for app in approvals if app.get("approval_id")
        }

    def evaluate(self, event: dict[str, Any]) -> dict[str, Any] | None:
        action = event.get("action", "")
        role_before = event.get("role_before", "")
        role_after = event.get("role_after", "")

        is_role_change = (
            action in ("role_change", "privilege_escalation", "grant_role")
            or (role_before != role_after and role_after in ("admin", "superadmin", "operator", "database_admin"))
        )

        if not is_role_change:
            return None

        actor = event.get("actor", "unknown")
        approval_id = event.get("approval_id")

        # 1. Approval missing
        if not approval_id:
            return {
                "alert_id": f"alt_{uuid.uuid4().hex[:10]}",
                "actor": actor,
                "rule": self.RULE_NAME,
                "reason": (
                    f"Privilege change to '{role_after}' by actor '{actor}' executed "
                    f"without required approval_id."
                ),
                "event_ids": [event["event_id"]],
                "source_service": event.get("source_service", ""),
                "target_service": event.get("target_service", ""),
                "event_time_utc": event.get("event_time_utc", ""),
                "severity": "CRITICAL",
            }

        # 2. Approval ID not found in approvals database
        if approval_id not in self.approvals_by_id:
            return {
                "alert_id": f"alt_{uuid.uuid4().hex[:10]}",
                "actor": actor,
                "rule": self.RULE_NAME,
                "reason": (
                    f"Privilege change to '{role_after}' references unknown or invalid "
                    f"approval_id '{approval_id}'."
                ),
                "event_ids": [event["event_id"]],
                "source_service": event.get("source_service", ""),
                "target_service": event.get("target_service", ""),
                "event_time_utc": event.get("event_time_utc", ""),
                "severity": "CRITICAL",
            }

        approval = self.approvals_by_id[approval_id]

        # 3. Approval status check
        if approval.get("status") != "approved":
            return {
                "alert_id": f"alt_{uuid.uuid4().hex[:10]}",
                "actor": actor,
                "rule": self.RULE_NAME,
                "reason": (
                    f"Privilege change references approval '{approval_id}' but its status is "
                    f"'{approval.get('status')}', not approved."
                ),
                "event_ids": [event["event_id"]],
                "source_service": event.get("source_service", ""),
                "target_service": event.get("target_service", ""),
                "event_time_utc": event.get("event_time_utc", ""),
                "severity": "CRITICAL",
            }

        # 4. Approval does not match actor or role
        if approval.get("actor") and approval["actor"] != actor:
            return {
                "alert_id": f"alt_{uuid.uuid4().hex[:10]}",
                "actor": actor,
                "rule": self.RULE_NAME,
                "reason": (
                    f"Approval '{approval_id}' was issued for actor '{approval.get('actor')}', "
                    f"not for actor '{actor}'."
                ),
                "event_ids": [event["event_id"]],
                "source_service": event.get("source_service", ""),
                "target_service": event.get("target_service", ""),
                "event_time_utc": event.get("event_time_utc", ""),
                "severity": "CRITICAL",
            }

        # All validation passed -> legitimate approved work
        return None


class LateralMovementRule:
    """RULE 2: LATERAL_MOVEMENT_FIRST_PATH.

    Tracks service relationships for each actor.
    If an actor creates a service path never previously observed for that actor,
    creates an alert.
    """

    RULE_NAME = "LATERAL_MOVEMENT_FIRST_PATH"

    def __init__(
        self,
        known_paths: dict[str, list[tuple[str, str]] | set[tuple[str, str]]] | None = None,
    ) -> None:
        self.observed_paths: dict[str, set[tuple[str, str]]] = defaultdict(set)
        if known_paths is not None:
            for actor, paths in known_paths.items():
                self.observed_paths[actor].update(paths)
        else:
            # Initialize with default baseline paths
            for actor, paths in USER_NORMAL_PATHS.items():
                self.observed_paths[actor].update(paths)

    def evaluate(self, event: dict[str, Any]) -> dict[str, Any] | None:
        actor = event.get("actor")
        src = event.get("source_service")
        dst = event.get("target_service")

        if not (actor and src and dst):
            return None

        path = (src, dst)

        # Check if path has been observed for this actor
        if path not in self.observed_paths[actor]:
            # Alert on the first-time traversal
            reason = (
                f"Lateral movement detected: actor '{actor}' initiated communication along "
                f"previously unobserved service path '{src} -> {dst}'."
            )
            # Record it so we don't alert repeatedly on the same path
            self.observed_paths[actor].add(path)

            return {
                "alert_id": f"alt_{uuid.uuid4().hex[:10]}",
                "actor": actor,
                "rule": self.RULE_NAME,
                "reason": reason,
                "event_ids": [event["event_id"]],
                "source_service": src,
                "target_service": dst,
                "event_time_utc": event.get("event_time_utc", ""),
                "severity": "HIGH",
            }

        return None


class DataAccessSpikeRule:
    """RULE 3: DATA_ACCESS_SPIKE.

    Calculates a baseline for each user's data-access behaviour.
    Uses transparent statistical thresholding:
    Triggers when data access frequency in a sliding window exceeds
    baseline mean + statistical threshold.
    """

    RULE_NAME = "DATA_ACCESS_SPIKE"

    DATA_ACTIONS: ClassVar[set[str]] = {
        "database_read",
        "read",
        "query",
        "export",
        "select",
        "fetch",
    }

    def __init__(
        self,
        baseline_means: dict[str, int | float] | None = None,
        window_seconds: float = 60.0,
        threshold_multiplier: float = 3.0,
        min_spike_count: int = 15,
    ) -> None:
        self.baseline_means = (
            dict(baseline_means) if baseline_means is not None else dict(USER_DATA_ACCESS_BASELINE)
        )
        self.window_seconds = window_seconds
        self.threshold_multiplier = threshold_multiplier
        self.min_spike_count = min_spike_count

        # Track recent read events per actor: list of (timestamp, event_id, event)
        self.actor_history: dict[str, list[tuple[datetime, str, dict[str, Any]]]] = defaultdict(list)
        # Track last alert timestamp per actor to suppress duplicate alerts within same burst window
        self.last_alert_time: dict[str, datetime] = {}

    def _is_data_access(self, event: dict[str, Any]) -> bool:
        action = event.get("action", "").lower()
        target = event.get("target_service", "").lower()
        return action in self.DATA_ACTIONS or (target == "database" and "write" not in action)

    def evaluate_batch(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Evaluate events in chronological order for data access spikes."""
        alerts: list[dict[str, Any]] = []

        for evt in events:
            if not self._is_data_access(evt):
                continue

            actor = evt.get("actor", "unknown")
            event_id = evt.get("event_id", "")
            ts_str = evt.get("corrected_time_utc") or evt.get("event_time_utc")
            if not ts_str:
                continue

            event_dt = parse_iso_timestamp(ts_str)
            history = self.actor_history[actor]
            history.append((event_dt, event_id, evt))

            # Prune events older than window
            cutoff = event_dt.timestamp() - self.window_seconds
            self.actor_history[actor] = [
                item for item in history if item[0].timestamp() >= cutoff
            ]
            current_window = self.actor_history[actor]

            count = len(current_window)
            baseline = self.baseline_means.get(actor, 5)
            # Threshold: either 3x baseline or min_spike_count
            threshold = max(baseline * self.threshold_multiplier, self.min_spike_count)

            if count >= threshold:
                last_time = self.last_alert_time.get(actor)
                if last_time is None or (event_dt - last_time).total_seconds() >= self.window_seconds:
                    self.last_alert_time[actor] = event_dt
                    burst_ids = [item[1] for item in current_window]
                    reason = (
                        f"Data access spike detected: actor '{actor}' performed {count} data access "
                        f"operations within {self.window_seconds}s window, exceeding baseline "
                        f"(baseline mean={baseline}, threshold={threshold})."
                    )
                    alerts.append(
                        {
                            "alert_id": f"alt_{uuid.uuid4().hex[:10]}",
                            "actor": actor,
                            "rule": self.RULE_NAME,
                            "reason": reason,
                            "event_ids": burst_ids,
                            "source_service": evt.get("source_service", ""),
                            "target_service": evt.get("target_service", ""),
                            "event_time_utc": evt.get("event_time_utc", ""),
                            "severity": "HIGH",
                        }
                    )

        return alerts
