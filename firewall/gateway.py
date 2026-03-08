from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional

from .engine import SecurityFirewall
from .types import Decision, Finding, PlannedAction, SecurityContext

_ALLOWED_GATEWAY_KEYS = {
    "user_input",
    "model_output",
    "planned_actions",
    "memory_reads",
    "memory_writes",
    "session_id",
    "turn_id",
    "agent_id",
    "metadata",
}
_MAX_TEXT_LEN = 50000
_MAX_COLLECTION_ITEMS = 256
_MAX_ITEM_LEN = 2048


@dataclass(frozen=True)
class GatewayRequest:
    user_input: str = ""
    model_output: str = ""
    planned_actions: List[PlannedAction] = field(default_factory=list)
    memory_reads: List[str] = field(default_factory=list)
    memory_writes: List[str] = field(default_factory=list)
    session_id: str = ""
    turn_id: str = ""
    agent_id: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_security_context(self) -> SecurityContext:
        return SecurityContext(
            user_input=self.user_input,
            model_output=self.model_output,
            planned_actions=list(self.planned_actions),
            memory_reads=list(self.memory_reads),
            memory_writes=list(self.memory_writes),
        )


@dataclass(frozen=True)
class GatewayDecision:
    decision: str
    total_score: float
    reasons: List[str]
    findings: List[Finding]
    request_id: str
    decided_at: str
    metadata: Dict[str, Any]
    session_id: str = ""
    turn_id: str = ""
    agent_id: str = ""


class AgentSecurityGateway:
    """Gateway facade over SecurityFirewall.

    Phase 1 goal: preserve existing firewall semantics while adding
    runtime-level envelope fields for agent integration.
    """

    def __init__(self, firewall: Optional[SecurityFirewall] = None) -> None:
        self.firewall = firewall or SecurityFirewall()

    @staticmethod
    def _coerce_text(name: str, raw: Any) -> str:
        value = str(raw or "")
        if len(value) > _MAX_TEXT_LEN:
            raise ValueError(f"{name} exceeds max length ({_MAX_TEXT_LEN})")
        return value

    @staticmethod
    def _coerce_identifier(name: str, raw: Any) -> str:
        value = str(raw or "").strip()
        if len(value) > _MAX_ITEM_LEN:
            raise ValueError(f"{name} exceeds max length ({_MAX_ITEM_LEN})")
        return value

    @staticmethod
    def _coerce_str_list(name: str, raw: Any) -> List[str]:
        if raw is None:
            return []
        if not isinstance(raw, list):
            raise ValueError(f"{name} must be a list of strings")
        if len(raw) > _MAX_COLLECTION_ITEMS:
            raise ValueError(f"{name} exceeds max items ({_MAX_COLLECTION_ITEMS})")
        result: List[str] = []
        for item in raw:
            text = str(item)
            if len(text) > _MAX_ITEM_LEN:
                raise ValueError(f"{name} entry exceeds max length ({_MAX_ITEM_LEN})")
            result.append(text)
        return result

    @staticmethod
    def _coerce_planned_actions(raw: Any) -> List[PlannedAction]:
        if raw is None:
            return []
        if not isinstance(raw, list):
            raise ValueError("planned_actions must be a list")
        if len(raw) > _MAX_COLLECTION_ITEMS:
            raise ValueError(f"planned_actions exceeds max items ({_MAX_COLLECTION_ITEMS})")

        actions: List[PlannedAction] = []
        for item in raw:
            if isinstance(item, str):
                if ":" in item:
                    action_type, target = item.split(":", 1)
                else:
                    action_type, target = item, ""
                target = target.strip()
                if len(target) > _MAX_ITEM_LEN:
                    raise ValueError(f"planned_actions target exceeds max length ({_MAX_ITEM_LEN})")
                actions.append(PlannedAction(action_type=action_type.strip(), target=target))
                continue

            if isinstance(item, Mapping):
                target = str(item.get("target", "")).strip()
                if len(target) > _MAX_ITEM_LEN:
                    raise ValueError(f"planned_actions target exceeds max length ({_MAX_ITEM_LEN})")
                actions.append(
                    PlannedAction(
                        action_type=str(item.get("action_type", "")).strip(),
                        target=target,
                    )
                )
                continue

            raise ValueError("planned_actions entries must be strings or objects")

        return actions

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> GatewayRequest:
        unknown = sorted(set(payload.keys()) - _ALLOWED_GATEWAY_KEYS)
        if unknown:
            raise ValueError(f"Unexpected gateway payload keys: {unknown}")

        metadata = payload.get("metadata", {})
        if not isinstance(metadata, dict):
            raise ValueError("metadata must be an object")
        if len(metadata) > _MAX_COLLECTION_ITEMS:
            raise ValueError(f"metadata exceeds max items ({_MAX_COLLECTION_ITEMS})")

        return GatewayRequest(
            user_input=cls._coerce_text("user_input", payload.get("user_input", "")),
            model_output=cls._coerce_text("model_output", payload.get("model_output", "")),
            planned_actions=cls._coerce_planned_actions(payload.get("planned_actions")),
            memory_reads=cls._coerce_str_list("memory_reads", payload.get("memory_reads")),
            memory_writes=cls._coerce_str_list("memory_writes", payload.get("memory_writes")),
            session_id=cls._coerce_identifier("session_id", payload.get("session_id", "")),
            turn_id=cls._coerce_identifier("turn_id", payload.get("turn_id", "")),
            agent_id=cls._coerce_identifier("agent_id", payload.get("agent_id", "")),
            metadata={str(k): v for k, v in metadata.items()},
        )

    def inspect(self, request: GatewayRequest) -> GatewayDecision:
        context = request.to_security_context()
        decision = self.firewall.inspect(context)
        return self._to_gateway_decision(decision, request)

    @staticmethod
    def _to_gateway_decision(decision: Decision, request: GatewayRequest) -> GatewayDecision:
        metadata = dict(decision.metadata)
        metadata.update(
            {
                "session_id": request.session_id,
                "turn_id": request.turn_id,
                "agent_id": request.agent_id,
                "gateway_metadata": request.metadata,
            }
        )
        return GatewayDecision(
            decision=decision.decision,
            total_score=decision.total_score,
            reasons=list(decision.reasons),
            findings=list(decision.findings),
            request_id=decision.request_id,
            decided_at=decision.decided_at,
            metadata=metadata,
            session_id=request.session_id,
            turn_id=request.turn_id,
            agent_id=request.agent_id,
        )
