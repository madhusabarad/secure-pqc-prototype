"""Deterministic timestamp and event order handling for distributed security logs."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

# Supported boundaries
MAX_CLOCK_SKEW_SECONDS = 120.0  # +/- 120s clock skew
MAX_LATE_ARRIVAL_SECONDS = 300.0  # up to 5 minutes late
UNCERTAINTY_WINDOW_SECONDS = 2.0  # related events within 2.0s are marked order_uncertain


def parse_iso_timestamp(ts: str | datetime) -> datetime:
    """Parse ISO 8601 string to timezone-aware UTC datetime."""
    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            return ts.replace(tzinfo=UTC)
        return ts.astimezone(UTC)

    # Standard ISO string parsing
    clean_ts = ts.replace("Z", "+00:00")
    dt = datetime.fromisoformat(clean_ts)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def correct_event_time(event: dict[str, Any]) -> tuple[datetime, datetime | None, float]:
    """Calculate true event time accounting for source_clock_offset_ms.

    A positive offset means source clock was ahead of true UTC:
      true_utc = event_time - offset
    A negative offset means source clock was behind true UTC:
      true_utc = event_time - (-offset) = event_time + abs(offset)

    Returns:
        tuple of (corrected_time, received_time, late_delay_seconds)
    """
    event_time = parse_iso_timestamp(event["event_time_utc"])
    offset_ms = int(event.get("source_clock_offset_ms", 0))
    corrected_time = event_time - timedelta(milliseconds=offset_ms)

    received_time = None
    late_delay_seconds = 0.0

    if event.get("received_time_utc"):
        received_time = parse_iso_timestamp(event["received_time_utc"])
        late_delay_seconds = (received_time - corrected_time).total_seconds()

    return corrected_time, received_time, late_delay_seconds


def is_order_uncertain(
    evt_a: dict[str, Any],
    corr_a: datetime,
    evt_b: dict[str, Any],
    corr_b: datetime,
) -> bool:
    """Check if the ordering between two related events is uncertain.

    Events are related if they share the same actor, session_id, or service path.
    Ordering is uncertain when:
    1. Corrected timestamps are identical or within the UNCERTAINTY_WINDOW_SECONDS.
    2. Corrected ordering contradicts the physical arrival order at the collector.
    """
    # Check relationship
    same_actor = evt_a.get("actor") and evt_a.get("actor") == evt_b.get("actor")
    same_session = evt_a.get("session_id") and evt_a.get("session_id") == evt_b.get("session_id")
    same_path = (
        evt_a.get("source_service") == evt_b.get("source_service")
        and evt_a.get("target_service") == evt_b.get("target_service")
    )

    if not (same_actor or same_session or same_path):
        return False

    time_diff = abs((corr_a - corr_b).total_seconds())

    # If within uncertainty window (clock jitter / resolution ambiguity)
    if time_diff <= UNCERTAINTY_WINDOW_SECONDS:
        return True

    # If received times are available and contradict corrected order
    recv_a_str = evt_a.get("received_time_utc")
    recv_b_str = evt_b.get("received_time_utc")
    if recv_a_str and recv_b_str:
        recv_a = parse_iso_timestamp(recv_a_str)
        recv_b = parse_iso_timestamp(recv_b_str)
        # If corr_a is before corr_b, but recv_a was received substantially later than recv_b
        # within skew tolerance, relative sequence has uncertainty
        if (
            corr_a < corr_b
            and recv_a > recv_b
            and time_diff <= MAX_CLOCK_SKEW_SECONDS / 10.0
        ):
            return True

    return False


def normalize_and_order_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Normalize timestamps, apply clock skew corrections, and sort deterministically.

    Preserves original event objects/data and attaches:
    - corrected_time_utc
    - late_delay_seconds
    - order_uncertain
    - original_event
    """
    if not events:
        return []

    processed: list[dict[str, Any]] = []

    for evt in events:
        try:
            corr_dt, _, delay_sec = correct_event_time(evt)
        except (ValueError, KeyError, TypeError):
            # Malformed timestamp fallback
            corr_dt = datetime.now(UTC)
            delay_sec = 0.0

        enriched = dict(evt)  # preserve all original fields
        enriched["original_event"] = evt
        enriched["_corr_dt"] = corr_dt
        enriched["corrected_time_utc"] = corr_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        enriched["late_delay_seconds"] = delay_sec
        enriched["order_uncertain"] = False
        processed.append(enriched)

    # Deterministic sort key: corrected event time, then received time, then event_id
    processed.sort(
        key=lambda e: (
            e["_corr_dt"],
            parse_iso_timestamp(e.get("received_time_utc", e["event_time_utc"])),
            str(e.get("event_id", "")),
        )
    )

    # Identify uncertain ordering among related adjacent events
    for i in range(len(processed)):
        current = processed[i]
        curr_dt = current["_corr_dt"]

        # Check adjacent predecessors and successors
        for j in (i - 1, i + 1):
            if 0 <= j < len(processed):
                neighbor = processed[j]
                neighbor_dt = neighbor["_corr_dt"]
                if is_order_uncertain(current, curr_dt, neighbor, neighbor_dt):
                    current["order_uncertain"] = True
                    neighbor["order_uncertain"] = True

    return processed
