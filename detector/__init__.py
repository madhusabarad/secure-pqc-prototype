"""detector package - Person D cybersecurity detector module."""

from detector.detector import SecurityDetector, run
from detector.rules import (
    DataAccessSpikeRule,
    LateralMovementRule,
    PrivilegeRule,
)
from detector.time_order import (
    correct_event_time,
    normalize_and_order_events,
    parse_iso_timestamp,
)

__all__ = [
    "DataAccessSpikeRule",
    "LateralMovementRule",
    "PrivilegeRule",
    "SecurityDetector",
    "correct_event_time",
    "normalize_and_order_events",
    "parse_iso_timestamp",
    "run",
]
