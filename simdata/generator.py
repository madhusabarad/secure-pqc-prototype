"""Deterministic security event generator and ground truth for Person D prototype."""

from __future__ import annotations

import json
import random
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

SERVICES = [
    "portal",
    "auth",
    "orders",
    "payments",
    "database",
    "reports",
]

USERS = [f"user{i:02d}" for i in range(1, 21)]

# Normal service-to-service paths by user persona
USER_NORMAL_PATHS: dict[str, list[tuple[str, str]]] = {
    # Customers / Basic Portal Users (user01 - user04)
    "user01": [("portal", "auth"), ("portal", "orders")],
    "user02": [("portal", "auth"), ("portal", "orders")],
    "user03": [("portal", "auth"), ("portal", "orders")],
    "user04": [("portal", "auth"), ("portal", "orders")],
    # Payment Operators (user05 - user08)
    "user05": [("portal", "auth"), ("portal", "orders"), ("orders", "payments"), ("orders", "database")],
    "user06": [("portal", "auth"), ("portal", "orders"), ("orders", "payments"), ("orders", "database")],
    "user07": [("portal", "auth"), ("portal", "orders"), ("orders", "payments"), ("orders", "database")],
    "user08": [("portal", "auth"), ("portal", "database"), ("orders", "payments")],
    # Database Engineers / Admins (user09 - user12)
    "user09": [("portal", "auth"), ("portal", "database"), ("database", "reports")],
    "user10": [("portal", "auth"), ("portal", "database"), ("database", "reports")],
    "user11": [("portal", "auth"), ("portal", "database"), ("database", "reports")],
    "user12": [("portal", "auth"), ("portal", "database"), ("database", "reports")],
    # Business Analysts (user13 - user16)
    "user13": [("portal", "auth"), ("portal", "reports"), ("reports", "database")],
    "user14": [("portal", "auth"), ("portal", "reports"), ("reports", "database")],
    "user15": [("portal", "auth"), ("portal", "reports"), ("reports", "database")],
    "user16": [("portal", "auth"), ("portal", "reports"), ("reports", "database")],
    # System Ops & Support (user17 - user20)
    "user17": [("portal", "auth"), ("orders", "database"), ("reports", "database")],
    "user18": [("portal", "auth"), ("orders", "database"), ("reports", "database")],
    "user19": [("portal", "auth"), ("orders", "database"), ("reports", "database")],
    "user20": [("portal", "auth"), ("orders", "database"), ("reports", "database")],
}

# Normal baseline data access reads per window/session
USER_DATA_ACCESS_BASELINE: dict[str, int] = {
    user: (4 if i < 8 else (8 if i < 16 else 5))
    for i, user in enumerate(USERS, start=1)
}


def load_approvals() -> list[dict[str, Any]]:
    """Load valid approval records from simdata/approvals.json."""
    approvals_path = Path(__file__).resolve().parent / "approvals.json"
    if approvals_path.exists():
        with open(approvals_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                return data
    return []


def generate_events(
    seed: int = 42,
    count: int = 1000,
    shuffle: bool = True,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Generate simulated security events and separate ground truth labels.

    Args:
        seed: Random seed for deterministic generation.
        count: Target number of benign and attack events to generate.
        shuffle: Whether to shuffle arrival order simulating network arrival.

    Returns:
        tuple of (events, ground_truth)
    """
    rng = random.Random(seed)
    base_time = datetime(2026, 11, 26, 8, 0, 0, tzinfo=UTC)
    approvals = load_approvals()

    events: list[dict[str, Any]] = []
    ground_truth: list[dict[str, Any]] = []

    evt_seq = 1

    def make_event(
        actor: str,
        source_service: str,
        target_service: str,
        action: str,
        role_before: str = "user",
        role_after: str = "user",
        outcome: str = "success",
        approval_id: str | None = None,
        event_dt: datetime | None = None,
        clock_offset_ms: int = 0,
        late_delay_seconds: float = 0.0,
    ) -> dict[str, Any]:
        nonlocal evt_seq
        if event_dt is None:
            event_dt = base_time + timedelta(seconds=evt_seq * 3)

        # Clock offset between -120s and +120s
        # Event time recorded by source clock: true_time + offset
        source_clock_time = event_dt + timedelta(milliseconds=clock_offset_ms)
        # Received time at central sink: true_time + transmission/late delay
        received_time = event_dt + timedelta(seconds=late_delay_seconds)

        event = {
            "event_id": f"evt_{evt_seq:05d}",
            "event_time_utc": source_clock_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "received_time_utc": received_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "source_clock_offset_ms": clock_offset_ms,
            "actor": actor,
            "source_service": source_service,
            "target_service": target_service,
            "action": action,
            "role_before": role_before,
            "role_after": role_after,
            "outcome": outcome,
            "approval_id": approval_id,
            "session_id": f"sess_{actor}_{evt_seq // 20:04d}",
            "correlation_id": f"corr_{evt_seq:05d}",
        }
        evt_seq += 1
        return event

    # 1. Generate Benign Activity across users
    # Pre-calculate count of benign events to leave room for injected attacks
    target_benign = max(count - 80, 500)

    for _ in range(target_benign):
        actor = rng.choice(USERS)
        allowed_paths = USER_NORMAL_PATHS[actor]
        src, dst = rng.choice(allowed_paths)

        if dst == "auth":
            action = rng.choice(["login", "logout", "token_refresh"])
        elif dst == "database":
            action = rng.choice(["database_read", "database_write", "query"])
        elif dst == "reports":
            action = rng.choice(["query", "export", "service_access"])
        elif dst == "orders":
            action = rng.choice(["service_access", "create_order", "query"])
        elif dst == "payments":
            action = rng.choice(["service_access", "process_payment"])
        else:
            action = "service_access"

        # Realistic clock offsets within +/- 120,000 ms (120s)
        # Mostly small offsets, occasional larger skews
        if rng.random() < 0.2:
            offset_ms = rng.randint(-120000, 120000)
        else:
            offset_ms = rng.randint(-15000, 15000)

        # Realistic network transit delays up to 10s, occasionally up to 300s (5 minutes late)
        if rng.random() < 0.05:
            late_sec = rng.uniform(60.0, 300.0)
        else:
            late_sec = rng.uniform(0.1, 5.0)

        events.append(
            make_event(
                actor=actor,
                source_service=src,
                target_service=dst,
                action=action,
                clock_offset_ms=offset_ms,
                late_delay_seconds=late_sec,
            )
        )

    # Add a few benign approved privilege changes (legitimate administrative work)
    for app in approvals[:2]:
        app_actor = app["actor"]
        approved_evt = make_event(
            actor=app_actor,
            source_service="portal",
            target_service="auth",
            action=app["approved_action"],
            role_before=app["role_before"],
            role_after=app["role_after"],
            outcome="success",
            approval_id=app["approval_id"],
            clock_offset_ms=rng.randint(-5000, 5000),
            late_delay_seconds=1.0,
        )
        events.append(approved_evt)

    # 2. Inject Attack 1: PRIVILEGE_WITHOUT_APPROVAL
    # user07 escalates role from user to admin with no approval
    unapproved_evt_1 = make_event(
        actor="user07",
        source_service="portal",
        target_service="auth",
        action="role_change",
        role_before="user",
        role_after="admin",
        outcome="success",
        approval_id=None,
        clock_offset_ms=-25000,
        late_delay_seconds=2.5,
    )
    events.append(unapproved_evt_1)
    ground_truth.append(
        {
            "attack_id": "attack_001",
            "category": "PRIVILEGE_WITHOUT_APPROVAL",
            "event_ids": [unapproved_evt_1["event_id"]],
            "actor": "user07",
        }
    )

    # Another privilege attack with forged / invalid approval ID
    unapproved_evt_2 = make_event(
        actor="user14",
        source_service="portal",
        target_service="auth",
        action="role_change",
        role_before="user",
        role_after="superadmin",
        outcome="success",
        approval_id="APR-FAKE-999",
        clock_offset_ms=45000,
        late_delay_seconds=3.0,
    )
    events.append(unapproved_evt_2)
    ground_truth.append(
        {
            "attack_id": "attack_002",
            "category": "PRIVILEGE_WITHOUT_APPROVAL",
            "event_ids": [unapproved_evt_2["event_id"]],
            "actor": "user14",
        }
    )

    # 3. Inject Attack 2: LATERAL_MOVEMENT
    # user08 normally accesses portal->database or orders->payments.
    # Injected new path: payments -> reports (never used by user08)
    lateral_evt_1 = make_event(
        actor="user08",
        source_service="payments",
        target_service="reports",
        action="service_access",
        clock_offset_ms=10000,
        late_delay_seconds=1.5,
    )
    events.append(lateral_evt_1)
    ground_truth.append(
        {
            "attack_id": "attack_003",
            "category": "LATERAL_MOVEMENT",
            "event_ids": [lateral_evt_1["event_id"]],
            "actor": "user08",
        }
    )

    # Another lateral movement: user02 (basic portal user) jumps from orders -> database
    lateral_evt_2 = make_event(
        actor="user02",
        source_service="orders",
        target_service="database",
        action="database_read",
        clock_offset_ms=-80000,
        late_delay_seconds=50.0,
    )
    events.append(lateral_evt_2)
    ground_truth.append(
        {
            "attack_id": "attack_004",
            "category": "LATERAL_MOVEMENT",
            "event_ids": [lateral_evt_2["event_id"]],
            "actor": "user02",
        }
    )

    # 4. Inject Attack 3: DATA_ACCESS_SPIKE
    # user12 baseline is ~8 database reads; inject burst of 40 reads within 30 seconds
    spike_event_ids: list[str] = []
    spike_base_time = base_time + timedelta(seconds=evt_seq * 3)
    for i in range(40):
        read_evt = make_event(
            actor="user12",
            source_service="portal",
            target_service="database",
            action="database_read",
            event_dt=spike_base_time + timedelta(seconds=i * 0.5),
            clock_offset_ms=rng.randint(-5000, 5000),
            late_delay_seconds=rng.uniform(0.5, 2.0),
        )
        events.append(read_evt)
        spike_event_ids.append(read_evt["event_id"])

    ground_truth.append(
        {
            "attack_id": "attack_005",
            "category": "DATA_ACCESS_SPIKE",
            "event_ids": spike_event_ids,
            "actor": "user12",
        }
    )

    # Another data spike for user03: baseline is ~4 reads; burst of 35 queries
    spike_event_ids_2: list[str] = []
    spike_base_time_2 = base_time + timedelta(seconds=evt_seq * 3)
    for i in range(35):
        read_evt = make_event(
            actor="user03",
            source_service="portal",
            target_service="orders",
            action="query",
            event_dt=spike_base_time_2 + timedelta(seconds=i * 0.4),
            clock_offset_ms=rng.randint(-10000, 10000),
            late_delay_seconds=rng.uniform(0.2, 1.5),
        )
        events.append(read_evt)
        spike_event_ids_2.append(read_evt["event_id"])

    ground_truth.append(
        {
            "attack_id": "attack_006",
            "category": "DATA_ACCESS_SPIKE",
            "event_ids": spike_event_ids_2,
            "actor": "user03",
        }
    )

    # Shuffling arrival order if requested
    if shuffle:
        # Shuffling simulates packets/events arriving out-of-order over network
        rng.shuffle(events)

    return events, ground_truth
