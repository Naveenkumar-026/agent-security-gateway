from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Request

from firewall.models import InspectInputRequest, InspectResponse, InspectToolCallRequest
from firewall.types import PlannedAction

router = APIRouter(prefix="/inspect", tags=["inspect"])


def _action_to_dict(action: Any) -> Dict[str, Any]:
    if hasattr(action, "model_dump"):
        return action.model_dump()
    if hasattr(action, "dict"):
        return action.dict()
    return {"action_type": str(getattr(action, "action_type", "")), "target": str(getattr(action, "target", ""))}


@router.post("/input", response_model=InspectResponse)
def inspect_input(payload: InspectInputRequest, request: Request) -> Dict[str, Any]:
    service = request.app.state.gateway_service
    planned_actions = [
        PlannedAction(
            action_type=_action_to_dict(a).get("action_type", ""),
            target=_action_to_dict(a).get("target", ""),
        )
        for a in payload.planned_actions
    ]
    return service.inspect(
        user_input=payload.user_input,
        model_output=payload.model_output,
        planned_actions=planned_actions,
        memory_reads=list(payload.memory_reads),
        memory_writes=list(payload.memory_writes),
        session_id=payload.session_id,
        turn_id=payload.turn_id,
        agent_id=payload.agent_id,
        gateway_metadata=dict(payload.metadata),
        approval_token=payload.approval_token,
    )


@router.post("/tool-call", response_model=InspectResponse)
def inspect_tool_call(payload: InspectToolCallRequest, request: Request) -> Dict[str, Any]:
    service = request.app.state.gateway_service
    return service.inspect(
        user_input=payload.user_input,
        model_output=payload.model_output,
        planned_actions=[PlannedAction(action_type=payload.tool_name, target=payload.tool_target)],
        memory_reads=list(payload.memory_reads),
        memory_writes=list(payload.memory_writes),
        session_id=payload.session_id,
        turn_id=payload.turn_id,
        agent_id=payload.agent_id,
        gateway_metadata=dict(payload.metadata),
        approval_token=payload.approval_token,
    )
