from __future__ import annotations

from typing import Any, Dict, Mapping, Optional

from .config import FirewallConfig, load_config
from .engine import SecurityFirewall
from .gateway import AgentSecurityGateway
from .types import PlannedAction, SecurityContext

_ALLOWED_INPUT_KEYS = {"user_input", "model_output", "planned_actions", "memory_reads", "memory_writes"}
_MAX_COLLECTION_ITEMS = 256


def _coerce_str_list(name: str, value: Any) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(f"{name} must be a list of strings")
    if len(value) > _MAX_COLLECTION_ITEMS:
        raise ValueError(f"{name} exceeds max items ({_MAX_COLLECTION_ITEMS})")
    return [str(x) for x in value]


def _coerce_planned_actions(value: Any) -> list[PlannedAction]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError("planned_actions must be a list")
    if len(value) > _MAX_COLLECTION_ITEMS:
        raise ValueError(f"planned_actions exceeds max items ({_MAX_COLLECTION_ITEMS})")

    planned_actions: list[PlannedAction] = []
    for item in value:
        if isinstance(item, str):
            if ":" in item:
                action_type, target = item.split(":", 1)
            else:
                action_type, target = item, ""
            planned_actions.append(PlannedAction(action_type=action_type.strip(), target=target.strip()))
            continue
        if isinstance(item, dict):
            planned_actions.append(
                PlannedAction(
                    action_type=str(item.get("action_type", "")).strip(),
                    target=str(item.get("target", "")).strip(),
                )
            )
            continue
        raise ValueError("planned_actions entries must be strings or objects")

    return planned_actions


def create_firewall(config_path: Optional[str] = None, config: Optional[FirewallConfig] = None) -> SecurityFirewall:
    return SecurityFirewall(config=config or load_config(config_path=config_path))


def inspect_payload(payload: Mapping[str, Any], firewall: Optional[SecurityFirewall] = None) -> Dict[str, Any]:
    unknown_keys = sorted(set(payload.keys()) - _ALLOWED_INPUT_KEYS)
    if unknown_keys:
        raise ValueError(f"Unexpected payload keys: {unknown_keys}")

    runtime = firewall or SecurityFirewall()

    ctx = SecurityContext(
        user_input=str(payload.get("user_input", "")),
        model_output=str(payload.get("model_output", "")),
        memory_reads=_coerce_str_list("memory_reads", payload.get("memory_reads")),
        memory_writes=_coerce_str_list("memory_writes", payload.get("memory_writes")),
        planned_actions=_coerce_planned_actions(payload.get("planned_actions")),
    )

    decision = runtime.inspect(ctx)
    return {
        "decision": decision.decision,
        "total_score": decision.total_score,
        "reasons": decision.reasons,
        "request_id": decision.request_id,
        "decided_at": decision.decided_at,
        "metadata": decision.metadata,
        "findings": [
            {
                "category": f.category,
                "severity": f.severity,
                "score": f.score,
                "message": f.message,
                "detector": f.detector,
                "metadata": f.metadata,
            }
            for f in decision.findings
        ],
    }


def inspect_gateway_payload(payload: Mapping[str, Any], firewall: Optional[SecurityFirewall] = None) -> Dict[str, Any]:
    """Gateway-style inspection with runtime envelope fields.

    This is additive and does not alter existing inspect_payload behavior.
    """
    gateway = AgentSecurityGateway(firewall=firewall or SecurityFirewall())
    request = gateway.from_payload(payload)
    decision = gateway.inspect(request)

    return {
        "decision": decision.decision,
        "total_score": decision.total_score,
        "reasons": decision.reasons,
        "request_id": decision.request_id,
        "decided_at": decision.decided_at,
        "session_id": decision.session_id,
        "turn_id": decision.turn_id,
        "agent_id": decision.agent_id,
        "metadata": decision.metadata,
        "findings": [
            {
                "category": f.category,
                "severity": f.severity,
                "score": f.score,
                "message": f.message,
                "detector": f.detector,
                "metadata": f.metadata,
            }
            for f in decision.findings
        ],
    }
