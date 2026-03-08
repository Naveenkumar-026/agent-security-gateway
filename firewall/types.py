from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal
from uuid import uuid4

Severity = Literal["low", "medium", "high", "critical"]
DecisionType = Literal["allow", "allow_with_redaction", "challenge", "block"]


@dataclass(frozen=True)
class PlannedAction:
    action_type: str
    target: str = ""

    def __post_init__(self) -> None:
        normalized_action = self.action_type.strip().lower()
        if not normalized_action:
            raise ValueError("PlannedAction.action_type cannot be empty")
        object.__setattr__(self, "action_type", normalized_action)
        object.__setattr__(self, "target", self.target.strip())


@dataclass(frozen=True)
class Finding:
    category: str
    severity: Severity
    score: float
    message: str
    detector: str
    metadata: Dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.category.strip():
            raise ValueError("Finding.category cannot be empty")
        if self.score < 0:
            raise ValueError("Finding.score must be >= 0")
        if not self.message.strip():
            raise ValueError("Finding.message cannot be empty")


@dataclass(frozen=True)
class SecurityContext:
    user_input: str = ""
    model_output: str = ""
    memory_reads: List[str] = field(default_factory=list)
    memory_writes: List[str] = field(default_factory=list)
    planned_actions: List[PlannedAction] = field(default_factory=list)
    request_id: str = field(default_factory=lambda: str(uuid4()))
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def __post_init__(self) -> None:
        if not any(
            [
                self.user_input.strip(),
                self.model_output.strip(),
                self.memory_reads,
                self.memory_writes,
                self.planned_actions,
            ]
        ):
            raise ValueError("SecurityContext must contain at least one non-empty signal")


@dataclass(frozen=True)
class Decision:
    decision: DecisionType
    total_score: float
    findings: List[Finding]
    reasons: List[str]
    request_id: str
    decided_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.total_score < 0:
            raise ValueError("Decision.total_score must be >= 0")
        if not self.request_id.strip():
            raise ValueError("Decision.request_id cannot be empty")
