"""Crash recovery with a write-ahead journal and a single commit point.

Commit protocol:
1. begin(kind, payload): write journal.json atomically via write-to-temp + fsync + os.replace.
2. commit(new_state): single atomic os.replace of new state.json (THE COMMIT POINT).
3. audit append: append audit event for the transaction.
4. complete(): delete journal.json.

Crash recovery semantics (run at process startup):
- If journal exists and commit happened: roll forward idempotently (ensure audit event exists by correlation_id, clear journal).
- If journal exists and commit did NOT happen:
    - If kind == "revoke": revocations are ALWAYS roll-forward! Re-apply revocation to state.json, commit, ensure audit event exists, clear journal.
    - Other kinds: roll back by discarding pending intent (delete journal.json).
"""

import json
import os
from pathlib import Path
import secrets
from typing import Any, Callable, Dict, Optional

from auditlog import audit
from auditlog.store import (
    file_lock,
    fsync_dir_if_supported,
    get_state_dir,
    load_state,
    save_state,
)


def get_journal_path() -> Path:
    return get_state_dir() / "journal.json"


class Journal:
    """Manages transactional state changes with atomic commit."""

    def __init__(self, kind: str, payload: Dict[str, Any]):
        self.kind = kind
        self.payload = payload
        self.tx_id = secrets.token_hex(16)
        self.committed = False

    def begin(self) -> None:
        """Write journal.json atomically (intent phase)."""
        journal_path = get_journal_path()
        tmp_path = journal_path.with_name(f"journal.json.tmp.{secrets.token_hex(8)}")
        data = {
            "tx_id": self.tx_id,
            "kind": self.kind,
            "payload": self.payload,
        }
        encoded = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
        with open(tmp_path, "w", encoding="utf-8") as f:
            f.write(encoded)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, journal_path)
        fsync_dir_if_supported(journal_path.parent)

    def commit(self, new_state: Dict[str, Any]) -> None:
        """Single atomic os.replace of state.json (THE COMMIT POINT)."""
        new_state = dict(new_state)
        new_state["last_tx_id"] = self.tx_id
        save_state(new_state)
        self.committed = True

    def complete(self) -> None:
        """Complete the transaction by removing journal.json."""
        journal_path = get_journal_path()
        if journal_path.exists():
            try:
                os.unlink(journal_path)
                fsync_dir_if_supported(journal_path.parent)
            except OSError:
                pass


def recover() -> None:
    """Idempotent crash recovery executed at every process startup."""
    journal_path = get_journal_path()
    if not journal_path.exists():
        return

    with file_lock():
        if not journal_path.exists():
            return

        try:
            with open(journal_path, "r", encoding="utf-8") as f:
                journal_data = json.load(f)
        except Exception:
            # Corrupted journal file: remove safely
            try:
                os.unlink(journal_path)
            except OSError:
                pass
            return

        tx_id = journal_data.get("tx_id")
        kind = journal_data.get("kind")
        payload = journal_data.get("payload", {})
        current_state = load_state()

        if current_state is None:
            # No state exists to recover against
            try:
                os.unlink(journal_path)
            except OSError:
                pass
            return

        commit_happened = current_state.get("last_tx_id") == tx_id

        if kind == "revoke":
            actor = payload.get("actor")
            corr_id = payload.get("request_id") or tx_id

            if not commit_happened:
                # Revocations are ALWAYS roll-forward: re-apply immediately
                revoked_list = list(current_state.get("revoked", []))
                if actor and actor not in revoked_list:
                    revoked_list.append(actor)
                current_state["revoked"] = revoked_list
                current_state["last_tx_id"] = tx_id
                save_state(current_state)

            # Ensure audit event exists idempotently
            if corr_id:
                existing = audit.find_event_by_correlation_id(corr_id)
                if not existing:
                    audit.append_event(
                        actor=actor or "system",
                        action="revoke",
                        outcome="success",
                        correlation_id=corr_id,
                    )

            # Clean up journal
            try:
                os.unlink(journal_path)
                fsync_dir_if_supported(journal_path.parent)
            except OSError:
                pass

        else:
            # Generic transaction recovery (e.g. key rotation)
            if commit_happened:
                # Roll forward: ensure audit event exists if correlation_id provided
                corr_id = payload.get("correlation_id") or tx_id
                action = payload.get("action", kind)
                actor = payload.get("actor", "system")
                existing = audit.find_event_by_correlation_id(corr_id)
                if not existing:
                    audit.append_event(
                        actor=actor,
                        action=action,
                        outcome="success",
                        correlation_id=corr_id,
                    )
                try:
                    os.unlink(journal_path)
                    fsync_dir_if_supported(journal_path.parent)
                except OSError:
                    pass
            else:
                # Roll back: discard pending uncommitted change
                try:
                    os.unlink(journal_path)
                    fsync_dir_if_supported(journal_path.parent)
                except OSError:
                    pass


def execute_revoke(actor: str, request_id: str = "") -> None:
    """Execute atomic revocation with crash recovery guarantee."""
    with file_lock():
        current_state = load_state()
        if current_state is None:
            raise RuntimeError("Cannot revoke on uninitialized state.")

        corr_id = request_id or secrets.token_hex(16)
        journal = Journal(kind="revoke", payload={"actor": actor, "request_id": corr_id})

        # Step 1: Intent
        journal.begin()

        # Step 2: Commit point
        new_state = dict(current_state)
        revoked_list = list(new_state.get("revoked", []))
        if actor not in revoked_list:
            revoked_list.append(actor)
        new_state["revoked"] = revoked_list
        journal.commit(new_state)

        # Step 3: Audit event
        audit.append_event(
            actor=actor,
            action="revoke",
            outcome="success",
            correlation_id=corr_id,
        )

        # Step 4: Complete transaction
        journal.complete()


def transactional_update(
    kind: str,
    payload: Dict[str, Any],
    update_fn: Callable[[Dict[str, Any]], Dict[str, Any]],
    audit_actor: str = "system",
    audit_action: str = "update",
    correlation_id: str = "",
) -> Dict[str, Any]:
    """Execute generic transactional update with crash protection."""
    with file_lock():
        current_state = load_state()
        if current_state is None:
            raise RuntimeError("Cannot execute transaction on uninitialized state.")

        corr_id = correlation_id or secrets.token_hex(16)
        journal_payload = dict(payload)
        journal_payload["correlation_id"] = corr_id
        journal_payload["action"] = audit_action
        journal_payload["actor"] = audit_actor

        journal = Journal(kind=kind, payload=journal_payload)

        # 1. Intent
        journal.begin()

        # 2. Commit
        updated_state = update_fn(dict(current_state))
        journal.commit(updated_state)

        # 3. Audit
        audit.append_event(
            actor=audit_actor,
            action=audit_action,
            outcome="success",
            correlation_id=corr_id,
        )

        # 4. Complete
        journal.complete()
        return updated_state
