# Person D Module: Security Guard & Anomaly Detector

> **"The detector uses deterministic rules and simple statistics. It does not use AI or machine learning."**

---

## 1. Detector Purpose

The detector acts as an automated security guard in a distributed zero-trust system. It ingests structured security and audit events, handles distributed clock skew and out-of-order delivery, applies deterministic security rules and simple statistical baselines, and emits explainable alerts with full context for forensic analysis.

---

## 2. Why Rule- & Statistics-Based Detection?

In mission-critical cybersecurity and post-quantum environments:
- **Explainability**: Every security alert includes human-auditable reasons linking directly to policy violations or statistical thresholds, with no "black box" decisions.
- **Determinism**: The same sequence of events consistently yields identical alerts, crucial for legal auditing, incident response, and regression testing.
- **Low Latency & High Throughput**: Fast evaluation without GPU requirements or inference overhead.
- **No Poisoning Risk**: Adversaries cannot manipulate neural network weights through crafted training samples.

---

## 3. The Three Detection Rules

### Rule 1: `PRIVILEGE_CHANGE_WITHOUT_APPROVAL`
- **Logic**: Evaluates privilege escalations and role modifications (`role_change`, `privilege_escalation`, etc.).
- **Triggers**: Fired when a role change occurs and:
  1. Required `approval_id` is absent/null, OR
  2. `approval_id` is not present in the valid approvals registry (`simdata/approvals.json`), OR
  3. Approval status is not `approved`, OR
  4. Approval record does not match the requesting actor or target role.
- **False-Positive Prevention**: Legitimate approved administrative role changes referencing valid records are permitted and never trigger an alert.

### Rule 2: `LATERAL_MOVEMENT_FIRST_PATH`
- **Logic**: Tracks communication paths `(source_service, target_service)` traversed by each actor against their normal operational profiles.
- **Triggers**: If an actor initiates communication along a service-to-service path never previously observed or authorized for that actor (e.g., `payments -> reports` for a database user), an alert is triggered immediately on first traversal.

### Rule 3: `DATA_ACCESS_SPIKE`
- **Logic**: Establishes a transparent baseline of read/query frequency per user (e.g. ~4–8 reads per session).
- **Triggers**: When an actor's data read operations in a sliding window (default 60s) exceed $\max(3 \times \text{baseline}, 15)$, a spike alert is raised with all triggering event IDs. Cooldown logic prevents duplicate notifications during the same burst.

---

## 4. Distributed Timestamp & Order Handling

Distributed services run on decoupled clocks and asynchronous networks. The detector module (`detector/time_order.py`) provides robust handling for:
- **Clock Skew (±120 seconds)**: Accounts for `source_clock_offset_ms` to recover true UTC reference time:
  $$\text{True UTC} = \text{event\_time\_utc} - \text{source\_clock\_offset\_ms}$$
- **Late Arrivals (up to 5 minutes / 300 seconds)**: Tracks network transit delay via `received_time_utc` and sorts reordered events into proper chronological order.
- **Uncertain Order Flagging**: When two related events (sharing actor, session, or path) occur within a 2.0-second jitter window or exhibit arrival contradictions, the detector preserves both events and explicitly sets `order_uncertain = true` rather than guessing an artificial order.

---

## 5. Example Alert Format

```json
{
  "alert_id": "alt_e7f3a1b02c",
  "actor": "user07",
  "rule": "PRIVILEGE_CHANGE_WITHOUT_APPROVAL",
  "reason": "Privilege change to 'admin' by actor 'user07' executed without required approval_id.",
  "event_ids": ["evt_00923"],
  "source_service": "portal",
  "target_service": "auth",
  "event_time_utc": "2026-11-26T08:46:09Z",
  "severity": "CRITICAL"
}
```

---

## 6. Generator Usage (`simdata`)

```python
from simdata import generate_events, load_approvals

# Generate 1,000 deterministic simulated events and ground truth
events, ground_truth = generate_events(seed=42, count=1000, shuffle=True)

print(f"Generated {len(events)} events with {len(ground_truth)} injected attacks.")
```

---

## 7. Evaluator Usage & Metrics

### Running the Evaluator
```bash
python -m detector.evaluator
```

### Metrics Definition
1. **Precision**: $\frac{\text{TP}}{\text{TP} + \text{FP}}$
2. **Recall**: $\frac{\text{TP}}{\text{TP} + \text{FN}}$
3. **F1 Score**: $2 \times \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}}$
4. **False Alerts / 1000 Benign Events**:
   $$\frac{\text{FP}}{\text{Total Benign Events}} \times 1000$$
5. **Median Time To Alert**:
   $$\text{Median}(\text{Alert Received Time} - \text{Suspicious Event Time})$$
   Calculated across all True Positive detections in seconds.

---

## 8. Running Tests

```bash
pytest
ruff check detector simdata tests
```
