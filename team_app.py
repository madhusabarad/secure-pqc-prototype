"""Team application request dispatcher.

Handles setup, read, revoke, audit, and protected_read operations.
Enforces strict input validation, crash recovery, persistent access control,
and tamper-evident audit logging.
"""

from typing import Any, Dict

from app import access, audit, recovery, store

try:
    from messaging.protected_read import protected_read as _kem_protected_read
except ImportError:
    _kem_protected_read = None

KNOWN_OPS = {"setup", "read", "revoke", "audit", "protected_read", "reenrol", "rotate"}
MAX_ID_LEN = 256


def _validate_str_id(value: Any, name: str) -> str:
    """Validate opaque string identifiers."""
    if not isinstance(value, str) or len(value) == 0 or len(value) > MAX_ID_LEN:
        raise ValueError(f"Invalid identifier for {name}")
    return value


def dispatch(request: Dict[str, Any]) -> Dict[str, Any]:
    """Dispatch a single request in a fresh process."""
    if not isinstance(request, dict):
        raise ValueError("Request must be a JSON object.")

    op = request.get("op")
    if not isinstance(op, str) or op not in KNOWN_OPS:
        raise ValueError("Unknown or missing operation.")

    # Always execute crash recovery at startup before processing the request
    recovery.recover()

    if op == "setup":
        owners_raw = request.get("owners")
        contents_raw = request.get("contents")
        disabled_raw = request.get("disabled", [])
        key_material = request.get("key_material", "")

        if not isinstance(owners_raw, dict) or not isinstance(contents_raw, dict) or not isinstance(disabled_raw, list):
            raise ValueError("Invalid setup payload structure.")
        if not isinstance(key_material, str):
            raise ValueError("key_material must be a string.")

        # Validate owners and contents
        owners = {}
        for asset, actor in owners_raw.items():
            owners[_validate_str_id(asset, "asset")] = _validate_str_id(actor, "actor")

        contents = {}
        for asset, body in contents_raw.items():
            if not isinstance(body, str):
                raise ValueError("Asset body must be a string.")
            contents[_validate_str_id(asset, "asset")] = body

        disabled = [_validate_str_id(d, "disabled_actor") for d in disabled_raw]

        with store.file_lock():
            # Reset audit log and checkpoint for a clean setup
            audit.reset_audit_log()
            # Initialize state file
            store.init_state(owners, contents, disabled, key_material)
            # Create fresh audit signing key
            audit.get_or_create_signing_key()
            # Record setup event in audit log
            audit.append_event(
                actor="system",
                action="setup",
                outcome="success",
                correlation_id="setup",
            )

        return {"ready": True}

    # All other operations require existing state
    current_state = store.load_state()
    if current_state is None:
        raise ValueError("Adapter state not initialized.")

    if op == "read":
        # Enforce actor from request field only, never from extra parameters
        actor = _validate_str_id(request.get("actor"), "actor")
        asset = _validate_str_id(request.get("asset"), "asset")
        request_id = _validate_str_id(request.get("request_id"), "request_id")

        decision = access.decide(current_state, actor, asset)

        if decision == "allow":
            body = current_state.get("contents", {}).get(asset, "")
            response = {"decision": "allow", "body": body}
        else:
            response = {"decision": "deny"}

        with store.file_lock():
            audit.append_event(
                actor=actor,
                action="read",
                outcome=decision,
                correlation_id=request_id,
            )

        return response

    elif op == "revoke":
        actor = _validate_str_id(request.get("actor"), "actor")
        request_id = request.get("request_id", "")
        if request_id:
            request_id = _validate_str_id(request_id, "request_id")

        recovery.execute_revoke(actor, request_id=request_id)
        return {}

    elif op == "reenrol":
        actor = _validate_str_id(request.get("actor"), "actor")
        new_device = _validate_str_id(request.get("new_device", "dev-re-enrolled"), "new_device")
        request_id = request.get("request_id", "")
        corr_id = _validate_str_id(request_id, "request_id") if request_id else f"reenrol-{actor}"

        def _reenrol_fn(st: Dict[str, Any]) -> Dict[str, Any]:
            revoked = [r for r in st.get("revoked", []) if r != actor]
            disabled = [d for d in st.get("disabled", []) if d != actor]
            st["revoked"] = revoked
            st["disabled"] = disabled
            devices = dict(st.get("devices", {}))
            devices[actor] = new_device
            st["devices"] = devices
            return st

        recovery.transactional_update(
            kind="reenrol",
            payload={"actor": actor, "new_device": new_device},
            update_fn=_reenrol_fn,
            audit_actor=actor,
            audit_action="reenrol",
            correlation_id=corr_id,
        )
        return {"ready": True, "actor": actor, "reenrolled": True}

    elif op == "rotate":
        new_key = request.get("key_material")
        if not isinstance(new_key, str) or not new_key:
            import secrets
            new_key = secrets.token_hex(16)
        request_id = request.get("request_id", "")
        corr_id = _validate_str_id(request_id, "request_id") if request_id else "rot-key"

        def _rotate_fn(st: Dict[str, Any]) -> Dict[str, Any]:
            st["key_version"] = st.get("key_version", 1) + 1
            st["key_material"] = new_key
            return st

        new_st = recovery.transactional_update(
            kind="rotate",
            payload={"key_version": current_state.get("key_version", 1) + 1},
            update_fn=_rotate_fn,
            audit_actor="system",
            audit_action="key_rotation",
            correlation_id=corr_id,
        )
        return {"ready": True, "key_version": new_st["key_version"]}

    elif op == "audit":
        request_id = _validate_str_id(request.get("request_id"), "request_id")
        event = audit.find_event_by_correlation_id(request_id)

        if event is not None:
            return {"request_id": request_id, "decision": event.get("outcome", "deny")}
        return {"request_id": request_id, "decision": "deny"}

    elif op == "protected_read":
        actor = _validate_str_id(request.get("actor"), "actor")
        asset = _validate_str_id(request.get("asset"), "asset")
        challenge = request.get("challenge")
        public_key = request.get("public_key")
        request_id = request.get("request_id", "")
        if request_id:
            request_id = _validate_str_id(request_id, "request_id")

        if not isinstance(challenge, str) or not isinstance(public_key, str):
            raise ValueError("Invalid challenge or public_key format.")

        decision = access.decide(current_state, actor, asset)
        corr_id = request_id or f"prot_{asset}"

        if decision != "allow":
            with store.file_lock():
                audit.append_event(
                    actor=actor,
                    action="protected_read",
                    outcome="deny",
                    correlation_id=corr_id,
                )
            return {"decision": "deny"}

        body = current_state.get("contents", {}).get(asset, "")
        res = None
        if _kem_protected_read is not None:
            try:
                res = _kem_protected_read(public_key, challenge, body)  # her order
            except Exception:
                res = None
        outcome = "allow" if res is not None else "deny"
        with store.file_lock():
            audit.append_event(
                actor=actor,
                action="protected_read",
                outcome=outcome,
                correlation_id=corr_id,
            )
        return res if res is not None else {"decision": "deny"}

    raise ValueError("Unhandled operation.")
