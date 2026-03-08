from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class StrictModel(BaseModel):
    class Config:
        extra = "forbid"


class PlannedActionModel(StrictModel):
    action_type: str = Field(min_length=1)
    target: str = ""


class InspectInputRequest(StrictModel):
    user_input: str = ""
    model_output: str = ""
    planned_actions: List[PlannedActionModel] = Field(default_factory=list)
    memory_reads: List[str] = Field(default_factory=list)
    memory_writes: List[str] = Field(default_factory=list)
    session_id: str = ""
    turn_id: str = ""
    agent_id: str = ""
    metadata: Dict[str, Any] = Field(default_factory=dict)
    approval_token: str = ""


class InspectToolCallRequest(StrictModel):
    tool_name: str = Field(min_length=1)
    tool_target: str = ""
    user_input: str = ""
    model_output: str = ""
    memory_reads: List[str] = Field(default_factory=list)
    memory_writes: List[str] = Field(default_factory=list)
    session_id: str = ""
    turn_id: str = ""
    agent_id: str = ""
    metadata: Dict[str, Any] = Field(default_factory=dict)
    approval_token: str = ""


class ApprovalSubmitRequest(StrictModel):
    session_id: str = Field(min_length=1)
    turn_id: str = ""
    agent_id: str = ""
    action_type: str = Field(min_length=1)
    action_target: str = ""
    expires_in_seconds: int = 900


class ApprovalResolveRequest(StrictModel):
    approval_id: str = Field(min_length=1)
    approve: bool
    resolver: str = Field(min_length=1)
    note: str = ""
    permit_ttl_seconds: int = 300


class FindingModel(StrictModel):
    category: str
    severity: str
    score: float
    message: str
    detector: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class InspectResponse(StrictModel):
    decision: str
    total_score: float
    reasons: List[str]
    request_id: str
    decided_at: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    findings: List[FindingModel] = Field(default_factory=list)
    session_id: Optional[str] = None
    turn_id: Optional[str] = None
    agent_id: Optional[str] = None
    approval: Optional[Dict[str, Any]] = None


class ApprovalResponse(StrictModel):
    approval_id: str
    status: str
    session_id: str
    turn_id: str
    agent_id: str
    action_type: str
    action_target: str
    created_at: str
    expires_at: str
    resolved_at: Optional[str] = None
    resolver: str = ""
    note: str = ""
    permit_token: str = ""
    permit_expires_at: Optional[str] = None


class HealthResponse(StrictModel):
    status: str


class ErrorResponse(StrictModel):
    error: str
    code: str
    details: Optional[Dict[str, Any]] = None
