"""Evaluation metrics engine for Person D cybersecurity detector."""

from __future__ import annotations

import statistics
from typing import Any

from detector.detector import run as detector_run
from detector.time_order import parse_iso_timestamp
from simdata.generator import generate_events

RULE_TO_CATEGORY_MAP = {
    "PRIVILEGE_CHANGE_WITHOUT_APPROVAL": "PRIVILEGE_WITHOUT_APPROVAL",
    "LATERAL_MOVEMENT_FIRST_PATH": "LATERAL_MOVEMENT",
    "DATA_ACCESS_SPIKE": "DATA_ACCESS_SPIKE",
}


def evaluate_detector(
    seed: int = 42,
    count: int = 1000,
    events: list[dict[str, Any]] | None = None,
    ground_truth: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Evaluate detector against ground truth on simulated security events.

    Metrics calculated:
    1. Precision = TP / (TP + FP)
    2. Recall = TP / (TP + FN)
    3. F1 Score = 2 * (Precision * Recall) / (Precision + Recall)
    4. False Alerts per 1,000 Benign Events = (FP / benign_events) * 1000
    5. Median Time To Alert = median(alert_time - suspicious_event_time) across TP alerts
       - suspicious_event_time: UTC timestamp when the suspicious action occurred (event_time_utc)
       - alert_time: UTC timestamp when the event was received and processed (received_time_utc)
    6. Category Coverage = detected_attacks_in_category / total_attacks_in_category
    """
    if events is None or ground_truth is None:
        events, ground_truth = generate_events(seed=seed, count=count)

    # Index events by event_id for fast lookup
    events_by_id = {e["event_id"]: e for e in events if "event_id" in e}

    # Identify all suspicious event IDs across ground truth
    all_suspicious_event_ids: set[str] = set()
    for gt in ground_truth:
        all_suspicious_event_ids.update(gt.get("event_ids", []))

    total_events = len(events)
    benign_events = max(total_events - len(all_suspicious_event_ids), 1)

    # Run detector
    alerts = detector_run(events)

    # Match alerts against ground-truth attacks
    matched_attacks: set[str] = set()
    tp_alerts: list[dict[str, Any]] = []
    fp_alerts: list[dict[str, Any]] = []

    for alert in alerts:
        alert_rule = alert.get("rule", "")
        alert_cat = RULE_TO_CATEGORY_MAP.get(alert_rule, alert_rule)
        alert_actor = alert.get("actor")
        alert_event_ids = set(alert.get("event_ids", []))

        # Check if alert matches any ground truth attack
        matched_attack_id: str | None = None
        for gt in ground_truth:
            gt_id = gt["attack_id"]
            gt_cat = gt["category"]
            gt_actor = gt["actor"]
            gt_eids = set(gt.get("event_ids", []))

            # Match criteria: same category, same actor, and overlapping event_ids
            if gt_cat == alert_cat and gt_actor == alert_actor and alert_event_ids.intersection(gt_eids):
                matched_attack_id = gt_id
                break

        if matched_attack_id:
            matched_attacks.add(matched_attack_id)
            tp_alerts.append(alert)
        else:
            fp_alerts.append(alert)

    tp = len(matched_attacks)
    fn = len(ground_truth) - tp
    fp = len(fp_alerts)

    # Precision, Recall, F1 with safe zero handling
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    # False alerts per 1,000 benign events
    false_alerts_per_1000 = (fp / benign_events) * 1000.0

    # Median Time To Alert: (alert received time - suspicious event time in seconds)
    time_to_alert_seconds: list[float] = []
    for alert in tp_alerts:
        alert_eids = alert.get("event_ids", [])
        if not alert_eids:
            continue
        first_eid = alert_eids[0]
        evt = events_by_id.get(first_eid)
        if evt and "event_time_utc" in evt and "received_time_utc" in evt:
            evt_time = parse_iso_timestamp(evt["event_time_utc"])
            recv_time = parse_iso_timestamp(evt["received_time_utc"])
            latency = abs((recv_time - evt_time).total_seconds())
            time_to_alert_seconds.append(latency)

    median_time_to_alert = (
        statistics.median(time_to_alert_seconds) if time_to_alert_seconds else 0.0
    )

    # Category Coverage
    categories = ["PRIVILEGE_WITHOUT_APPROVAL", "LATERAL_MOVEMENT", "DATA_ACCESS_SPIKE"]
    coverage: dict[str, dict[str, int | float]] = {}
    for cat in categories:
        cat_attacks = [gt for gt in ground_truth if gt["category"] == cat]
        total_cat = len(cat_attacks)
        detected_cat = sum(1 for gt in cat_attacks if gt["attack_id"] in matched_attacks)
        pct = (detected_cat / total_cat * 100.0) if total_cat > 0 else 0.0
        coverage[cat] = {
            "total": total_cat,
            "detected": detected_cat,
            "percentage": pct,
        }

    return {
        "f1_score": f1,
        "precision": precision,
        "recall": recall,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "total_events": total_events,
        "benign_events": benign_events,
        "false_alerts_per_1000": false_alerts_per_1000,
        "median_time_to_alert_seconds": median_time_to_alert,
        "coverage": coverage,
    }


def print_evaluation_report(results: dict[str, Any]) -> None:
    """Print the exact evaluation report expected by the project specification."""
    f1 = results["f1_score"]
    fp_rate = results["false_alerts_per_1000"]
    mtta = results["median_time_to_alert_seconds"]
    coverage = results["coverage"]

    print("========================================")
    print("DETECTOR EVALUATION")
    print("========================================")
    print(f"F1 Score:                          {f1:.4f}")
    print(f"False Alerts / 1000 Benign Events: {fp_rate:.2f}")
    print(f"Median Time To Alert:              {mtta:.2f} s")
    print("----------------------------------------")
    print("Detection Coverage by Attack Type:")
    for cat, stats in coverage.items():
        det = stats["detected"]
        tot = stats["total"]
        pct = stats["percentage"]
        print(f"  - {cat:<28} {det}/{tot} ({pct:.1f}%)")
    print("========================================")


if __name__ == "__main__":
    report = evaluate_detector(seed=42)
    print_evaluation_report(report)
