from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, List, Sequence

from .session_store import SessionState
from .types import Decision, Finding, PlannedAction

_SENSITIVE_ACTION_HINTS = {"exec_shell", "network_exfiltration", "permission_escalation", "read_memory", "write_filesystem"}


@dataclass(frozen=True)
class SessionRiskResult:
    extra_findings: List[Finding]
    updated_state: SessionState


class SessionRiskEngine:
    def __init__(
        self,
        repeat_action_threshold: int = 3,
        cumulative_challenge_threshold: float = 1.2,
        cumulative_block_threshold: float = 1.8,
    ) -> None:
        self.repeat_action_threshold = repeat_action_threshold
        self.cumulative_challenge_threshold = cumulative_challenge_threshold
        self.cumulative_block_threshold = cumulative_block_threshold

    @staticmethod
    def _append_history(existing: Sequence[str], incoming: Iterable[str], limit: int = 1024) -> List[str]:
        out = list(existing)
        for value in incoming:
            item = str(value).strip()
            if not item:
                continue
            out.append(item)
            if len(out) > limit:
                out = out[-limit:]
        return out

    @staticmethod
    def _unique_append(existing: Sequence[str], incoming: Iterable[str], limit: int = 256) -> List[str]:
        ordered = list(existing)
        seen = set(ordered)
        for value in incoming:
            item = str(value).strip()
            if not item or item in seen:
                continue
            ordered.append(item)
            seen.add(item)
            if len(ordered) >= limit:
                break
        return ordered

    @staticmethod
    def _extract_sensitive_markers(actions: Sequence[PlannedAction], memory_reads: Sequence[str], memory_writes: Sequence[str]) -> List[str]:
        markers: List[str] = []
        for action in actions:
            if action.action_type in _SENSITIVE_ACTION_HINTS:
                markers.append(f"action:{action.action_type}")
        for path in list(memory_reads) + list(memory_writes):
            lowered = path.lower()
            if any(token in lowered for token in ("secret", "vault", "token", "key", "credential")):
                markers.append(f"memory:{path}")
        return markers

    def evaluate(
        self,
        state: SessionState,
        decision: Decision,
        actions: Sequence[PlannedAction],
        memory_reads: Sequence[str],
        memory_writes: Sequence[str],
    ) -> SessionRiskResult:
        extra_findings: List[Finding] = []

        prior_counts = Counter(state.prior_actions)
        current_action_names = [a.action_type for a in actions]
        next_counts = prior_counts.copy()
        next_counts.update(current_action_names)

        for action_name in current_action_names:
            if action_name in _SENSITIVE_ACTION_HINTS and next_counts[action_name] >= self.repeat_action_threshold:
                extra_findings.append(
                    Finding(
                        category="unsafe_action_chain",
                        severity="high",
                        score=0.65,
                        message=f"Repeated sensitive action across session: {action_name}",
                        detector="session_risk",
                        metadata={"session_rule": "repeated_sensitive_action", "action": action_name},
                    )
                )

        prior_set = set(state.prior_actions)
        now_set = set(current_action_names)
        if "read_memory" in prior_set and "exec_shell" in now_set:
            extra_findings.append(
                Finding(
                    category="unsafe_action_chain",
                    severity="high",
                    score=0.75,
                    message="Session chain risk: prior memory read followed by shell execution.",
                    detector="session_risk",
                    metadata={"session_rule": "memory_then_shell"},
                )
            )
        if "read_memory" in prior_set and "write_filesystem" in now_set:
            extra_findings.append(
                Finding(
                    category="unsafe_action_chain",
                    severity="high",
                    score=0.7,
                    message="Session chain risk: prior memory read followed by filesystem write.",
                    detector="session_risk",
                    metadata={"session_rule": "memory_then_write"},
                )
            )

        new_cumulative_risk = max(0.0, state.cumulative_risk + decision.total_score)
        if new_cumulative_risk >= self.cumulative_block_threshold:
            extra_findings.append(
                Finding(
                    category="unsafe_action_chain",
                    severity="critical",
                    score=1.0,
                    message="Session cumulative risk exceeded block threshold.",
                    detector="session_risk",
                    metadata={
                        "session_rule": "cumulative_block_threshold",
                        "cumulative_risk": f"{new_cumulative_risk:.2f}",
                    },
                )
            )
        elif new_cumulative_risk >= self.cumulative_challenge_threshold:
            extra_findings.append(
                Finding(
                    category="unsafe_action_chain",
                    severity="high",
                    score=0.7,
                    message="Session cumulative risk exceeded challenge threshold.",
                    detector="session_risk",
                    metadata={
                        "session_rule": "cumulative_challenge_threshold",
                        "cumulative_risk": f"{new_cumulative_risk:.2f}",
                    },
                )
            )

        now = datetime.now(timezone.utc).isoformat()
        updated_state = SessionState(
            session_id=state.session_id,
            agent_id=state.agent_id,
            prior_actions=self._append_history(state.prior_actions, current_action_names),
            memory_touched=self._unique_append(state.memory_touched, list(memory_reads) + list(memory_writes)),
            cumulative_risk=new_cumulative_risk,
            prior_decisions=self._append_history(state.prior_decisions, [decision.decision]),
            sensitive_markers=self._unique_append(
                state.sensitive_markers,
                self._extract_sensitive_markers(actions, memory_reads, memory_writes),
            ),
            request_count=state.request_count + 1,
            created_at=state.created_at,
            updated_at=now,
            ended_at=state.ended_at,
        )
        return SessionRiskResult(extra_findings=extra_findings, updated_state=updated_state)
