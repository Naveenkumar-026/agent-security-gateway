from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Request

from firewall.models import ApprovalResolveRequest, ApprovalResponse, ApprovalSubmitRequest

router = APIRouter(prefix="/approval", tags=["approval"])


@router.post("/submit", response_model=ApprovalResponse)
def submit_approval(payload: ApprovalSubmitRequest, request: Request) -> Dict[str, Any]:
    service = request.app.state.gateway_service
    return service.submit_approval(
        session_id=payload.session_id,
        turn_id=payload.turn_id,
        agent_id=payload.agent_id,
        action_type=payload.action_type,
        action_target=payload.action_target,
        expires_in_seconds=payload.expires_in_seconds,
    )


@router.post("/resolve", response_model=ApprovalResponse)
def resolve_approval(payload: ApprovalResolveRequest, request: Request) -> Dict[str, Any]:
    service = request.app.state.gateway_service
    return service.resolve_approval(
        approval_id=payload.approval_id,
        approve=payload.approve,
        resolver=payload.resolver,
        note=payload.note,
        permit_ttl_seconds=payload.permit_ttl_seconds,
    )
