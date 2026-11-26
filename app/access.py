"""Access control engine stub for Saanvi.

Pure decision function and state transformation for actor revocation.
Saanvi will extend this module with richer policy rules, role checks, and delegation.
"""

from typing import Any, Dict


def decide(state: Dict[str, Any], actor: str, asset: str) -> str:
    """Evaluate whether an actor is authorized to read an asset.

    Pure function with no side effects.
    Rules enforced:
    1. Actor must not be in the disabled list.
    2. Actor must not be in the revoked list.
    3. Asset must exist in owners mapping and its owner must equal actor.

    Returns "allow" if all checks pass, otherwise "deny".
    """
    if not isinstance(state, dict):
        return "deny"

    disabled = state.get("disabled", [])
    if actor in disabled:
        return "deny"

    revoked = state.get("revoked", [])
    if actor in revoked:
        return "deny"

    owners = state.get("owners", {})
    if owners.get(asset) != actor:
        return "deny"

    return "allow"


def revoke(state: Dict[str, Any], actor: str) -> Dict[str, Any]:
    """Revoke an actor's access.

    Returns a shallow copy of the state dictionary with the actor appended
    to the revoked list if not already present. Revocation is persistent and
    survives process restarts.
    """
    new_state = dict(state)
    revoked_list = list(new_state.get("revoked", []))
    if actor not in revoked_list:
        revoked_list.append(actor)
    new_state["revoked"] = revoked_list
    return new_state
