from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Iterable, List, Optional, Tuple

from firewall.approval_store import ApprovalRecord, SQLiteApprovalStore
from firewall.audit_store import AuditEvent, SQLiteAuditStore
from firewall.engine import SecurityFirewall
from firewall.redaction import OutputRedactor
from firewall.session_risk import SessionRiskEngine
from firewall.session_store import SessionState, SQLiteSessionRiskStore
from firewall.types import Decision, Finding, PlannedAction, SecurityContext


class GatewayInspectionService:
    def __init__(
        self,
        firewall: SecurityFirewall,
        session_store: SQLiteSessionRiskStore,
        approval_store: SQLiteApprovalStore,
        audit_store: Optional[SQLiteAuditStore] = None,
        session_engine: Optional[SessionRiskEngine] = None,
    ) -> None:
        self.firewall = firewall
        self.session_store = session_store
        self.approval_store = approval_store
        self.audit_store = audit_store
        self.session_engine = session_engine or SessionRiskEngine()
        self.redactor = OutputRedactor(self.firewall.config.redaction)

    @staticmethod
    def _jsonable(value: Any) -> Any:
        if isinstance(value, dict):
            return {str(k): GatewayInspectionService._jsonable(v) for k, v in value.items()}
        if isinstance(value, (list, tuple, set)):
            return [GatewayInspectionService._jsonable(v) for v in value]
        if isinstance(value, (str, int, float, bool)) or value is None:
            return value
        if hasattr(value, "items"):
            return {str(k): GatewayInspectionService._jsonable(v) for k, v in value.items()}
        return str(value)

    @staticmethod
    def _serialize_findings(findings: Iterable[Finding]) -> List[Dict[str, Any]]:
        return [
            {
                "category": finding.category,
                "severity": finding.severity,
                "score": finding.score,
                "message": finding.message,
                "detector": finding.detector,
                "metadata": GatewayInspectionService._jsonable(dict(finding.metadata)),
            }
            for finding in findings
        ]

    @staticmethod
    def _serialize_decision(decision: Decision) -> Dict[str, Any]:
        return {
            "decision": decision.decision,
            "total_score": decision.total_score,
            "reasons": list(decision.reasons),
            "request_id": decision.request_id,
            "decided_at": decision.decided_at,
            "metadata": GatewayInspectionService._jsonable(dict(decision.metadata)),
            "findings": GatewayInspectionService._serialize_findings(decision.findings),
        }

    def sanitize_output(self, raw_output: str) -> Tuple[str, Dict[str, Any]]:
        result = self.redactor.redact_text(raw_output)
        redaction_metadata: Dict[str, Any] = {
            "redacted": result.redacted,
            "masked_count": len(result.events),
            "items": [
                {"kind": e.kind, "digest": e.digest, "length": e.length}
                for e in result.events
            ],
        }
        return result.sanitized_text, redaction_metadata

    @staticmethod
    def _normalized_string(value: str) -> str:
        return " ".join(str(value).strip().split())

    @classmethod
    def _normalize_actions(cls, planned_actions: List[PlannedAction]) -> List[Dict[str, str]]:
        normalized: List[Dict[str, str]] = []
        for action in planned_actions:
            normalized.append(
                {
                    "action_type": cls._normalized_string(action.action_type).lower(),
                    "target": cls._normalized_string(action.target),
                }
            )
        return normalized

    @classmethod
    def _normalize_memory(cls, values: List[str]) -> List[str]:
        return [cls._normalized_string(v) for v in values if cls._normalized_string(v)]

    @classmethod
    def _action_fingerprint(
        cls,
        *,
        session_id: str,
        agent_id: str,
        planned_actions: List[PlannedAction],
        memory_reads: List[str],
        memory_writes: List[str],
    ) -> str:
        payload = {
            "session_id": cls._normalized_string(session_id),
            "agent_id": cls._normalized_string(agent_id),
            "planned_actions": cls._normalize_actions(planned_actions),
            "memory_reads": cls._normalize_memory(memory_reads),
            "memory_writes": cls._normalize_memory(memory_writes),
        }
        text = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    @staticmethod
    def _approval_payload(record: ApprovalRecord) -> Dict[str, Any]:
        return {
            "approval_id": record.approval_id,
            "status": record.status,
            "session_id": record.session_id,
            "turn_id": record.turn_id,
            "agent_id": record.agent_id,
            "action_type": record.action_type,
            "action_target": record.action_target,
            "created_at": record.created_at,
            "expires_at": record.expires_at,
            "resolved_at": record.resolved_at,
            "resolver": record.resolver,
            "note": record.resolution_note,
            "permit_token": record.permit_token,
            "permit_expires_at": record.permit_expires_at,
        }

    def _apply_redaction_policy(self, decision: Decision, redaction: Optional[Dict[str, Any]]) -> Decision:
        if not redaction:
            return decision
        metadata = dict(decision.metadata)
        metadata["redaction"] = {
            "redacted": bool(redaction.get("redacted", False)),
            "masked_count": int(redaction.get("masked_count", 0)),
            "items": list(redaction.get("items", [])),
        }
        if (
            metadata["redaction"]["redacted"]
            and decision.decision == "allow"
            and self.firewall.config.policy.allow_with_redaction
        ):
            return Decision(
                decision="allow_with_redaction",
                total_score=decision.total_score,
                findings=decision.findings,
                reasons=list(decision.reasons) + ["Output sanitized by redaction policy."],
                request_id=decision.request_id,
                metadata=metadata,
            )
        return Decision(
            decision=decision.decision,
            total_score=decision.total_score,
            findings=decision.findings,
            reasons=decision.reasons,
            request_id=decision.request_id,
            metadata=metadata,
        )

    def _maybe_audit(
        self,
        *,
        session_id: str,
        turn_id: str,
        agent_id: str,
        planned_actions: List[PlannedAction],
        serialized_decision: Dict[str, Any],
    ) -> None:
        if self.audit_store is None:
            return
        primary = planned_actions[0] if planned_actions else PlannedAction(action_type="unknown", target="")
        self.audit_store.append_event(
            session_id=session_id,
            turn_id=turn_id,
            agent_id=agent_id,
            action_type=primary.action_type,
            action_target=primary.target,
            decision=str(serialized_decision.get("decision", "unknown")),
            total_score=float(serialized_decision.get("total_score", 0.0)),
            reasons=[str(x) for x in serialized_decision.get("reasons", [])],
            metadata=dict(serialized_decision.get("metadata", {})),
        )

    @staticmethod
    def _serialize_session(state: SessionState) -> Dict[str, Any]:
        return {
            "session_id": state.session_id,
            "agent_id": state.agent_id,
            "prior_actions": list(state.prior_actions),
            "memory_touched": list(state.memory_touched),
            "cumulative_risk": state.cumulative_risk,
            "prior_decisions": list(state.prior_decisions),
            "sensitive_markers": list(state.sensitive_markers),
            "request_count": state.request_count,
            "created_at": state.created_at,
            "updated_at": state.updated_at,
            "ended_at": state.ended_at,
        }

    def list_recent_sessions(self, limit: int = 50) -> List[Dict[str, Any]]:
        return [self._serialize_session(s) for s in self.session_store.list_recent(limit=limit)]

    def list_pending_approvals(self, limit: int = 50) -> List[Dict[str, Any]]:
        return [self._approval_payload(a) for a in self.approval_store.list_pending(limit=limit)]

    def list_recent_approvals(self, limit: int = 50) -> List[Dict[str, Any]]:
        return [self._approval_payload(a) for a in self.approval_store.list_recent(limit=limit)]

    @staticmethod
    def _serialize_event(event: AuditEvent) -> Dict[str, Any]:
        return {
            "event_id": event.event_id,
            "created_at": event.created_at,
            "session_id": event.session_id,
            "turn_id": event.turn_id,
            "agent_id": event.agent_id,
            "action_type": event.action_type,
            "action_target": event.action_target,
            "decision": event.decision,
            "total_score": event.total_score,
            "reasons": list(event.reasons),
            "metadata": dict(event.metadata),
        }

    def list_recent_events(self, limit: int = 100, only_flagged: bool = False) -> List[Dict[str, Any]]:
        if self.audit_store is None:
            return []
        events = [self._serialize_event(e) for e in self.audit_store.list_recent(limit=limit)]
        if only_flagged:
            events = [e for e in events if e["decision"] in {"block", "challenge", "require_approval"}]
        return events

    def get_session_timeline(self, session_id: str, limit: int = 200) -> List[Dict[str, Any]]:
        if self.audit_store is None:
            return []
        return [self._serialize_event(e) for e in self.audit_store.list_for_session(session_id=session_id, limit=limit)]

    def submit_approval(
        self,
        *,
        session_id: str,
        turn_id: str,
        agent_id: str,
        action_type: str,
        action_target: str,
        expires_in_seconds: int = 900,
    ) -> Dict[str, Any]:
        action = PlannedAction(action_type=action_type, target=action_target)
        fingerprint = self._action_fingerprint(
            session_id=session_id,
            agent_id=agent_id,
            planned_actions=[action],
            memory_reads=[],
            memory_writes=[],
        )
        record = self.approval_store.get_or_create_pending(
            session_id=session_id,
            turn_id=turn_id,
            agent_id=agent_id,
            action_fingerprint=fingerprint,
            action_type=action.action_type,
            action_target=action.target,
            expires_in_seconds=expires_in_seconds,
        )
        return self._approval_payload(record)

    def resolve_approval(
        self,
        *,
        approval_id: str,
        approve: bool,
        resolver: str,
        note: str,
        permit_ttl_seconds: int = 300,
    ) -> Dict[str, Any]:
        record = self.approval_store.resolve(
            approval_id=approval_id,
            approve=approve,
            resolver=resolver,
            note=note,
            permit_ttl_seconds=permit_ttl_seconds,
        )
        return self._approval_payload(record)

    def inspect(
        self,
        *,
        user_input: str,
        model_output: str,
        planned_actions: List[PlannedAction],
        memory_reads: List[str],
        memory_writes: List[str],
        session_id: str = "",
        turn_id: str = "",
        agent_id: str = "",
        gateway_metadata: Optional[Dict[str, Any]] = None,
        approval_token: str = "",
        redaction: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        ctx = SecurityContext(
            user_input=user_input,
            model_output=model_output,
            planned_actions=list(planned_actions),
            memory_reads=list(memory_reads),
            memory_writes=list(memory_writes),
        )
        base_decision = self.firewall.inspect(ctx)

        if not session_id.strip():
            final = self._apply_redaction_policy(base_decision, redaction)
            serialized = self._serialize_decision(final)
            serialized.update({"session_id": "", "turn_id": turn_id, "agent_id": agent_id})
            self._maybe_audit(
                session_id="",
                turn_id=turn_id,
                agent_id=agent_id,
                planned_actions=planned_actions,
                serialized_decision=serialized,
            )
            return serialized

        state = self.session_store.get_or_create(session_id=session_id, agent_id=agent_id)
        if agent_id and not state.agent_id:
            state.agent_id = agent_id

        session_risk = self.session_engine.evaluate(
            state=state,
            decision=base_decision,
            actions=planned_actions,
            memory_reads=memory_reads,
            memory_writes=memory_writes,
        )

        combined_findings = list(base_decision.findings) + list(session_risk.extra_findings)
        final_metadata = dict(base_decision.metadata)
        final_metadata.update(
            {
                "session_id": session_id,
                "turn_id": turn_id,
                "agent_id": agent_id,
                "gateway_metadata": dict(gateway_metadata or {}),
                "session_risk": {
                    "request_count": session_risk.updated_state.request_count,
                    "cumulative_risk": session_risk.updated_state.cumulative_risk,
                    "prior_action_count": len(session_risk.updated_state.prior_actions),
                    "memory_touched_count": len(session_risk.updated_state.memory_touched),
                    "sensitive_marker_count": len(session_risk.updated_state.sensitive_markers),
                },
            }
        )

        final_decision = self.firewall.policy.evaluate(
            findings=combined_findings,
            request_id=base_decision.request_id,
            metadata=final_metadata,
        )

        fingerprint = self._action_fingerprint(
            session_id=session_id,
            agent_id=agent_id,
            planned_actions=planned_actions,
            memory_reads=memory_reads,
            memory_writes=memory_writes,
        )

        if final_decision.decision == "challenge":
            permit = self.approval_store.consume_permit(
                permit_token=approval_token,
                session_id=session_id,
                agent_id=agent_id,
                action_fingerprint=fingerprint,
            )
            if permit is not None:
                final_metadata = dict(final_decision.metadata)
                final_metadata["approval"] = {
                    "approval_id": permit.approval_id,
                    "permit_used": True,
                    "status": permit.status,
                }
                final_decision = Decision(
                    decision="allow",
                    total_score=final_decision.total_score,
                    findings=final_decision.findings,
                    reasons=list(final_decision.reasons) + ["Execution approved by permit."],
                    request_id=final_decision.request_id,
                    metadata=final_metadata,
                )
            else:
                pending = self.approval_store.get_or_create_pending(
                    session_id=session_id,
                    turn_id=turn_id,
                    agent_id=agent_id,
                    action_fingerprint=fingerprint,
                    action_type=(planned_actions[0].action_type if planned_actions else "unknown"),
                    action_target=(planned_actions[0].target if planned_actions else ""),
                )
                serialized = self._serialize_decision(final_decision)
                serialized.update(
                    {
                        "decision": "require_approval",
                        "reasons": list(final_decision.reasons) + ["Human approval required before execution."],
                        "session_id": session_id,
                        "turn_id": turn_id,
                        "agent_id": agent_id,
                        "approval": self._approval_payload(pending),
                    }
                )
                self._maybe_audit(
                    session_id=session_id,
                    turn_id=turn_id,
                    agent_id=agent_id,
                    planned_actions=planned_actions,
                    serialized_decision=serialized,
                )
                return serialized

        final_decision = self._apply_redaction_policy(final_decision, redaction)

        self.session_store.upsert(session_risk.updated_state)
        serialized = self._serialize_decision(final_decision)
        serialized.update({"session_id": session_id, "turn_id": turn_id, "agent_id": agent_id})
        self._maybe_audit(
            session_id=session_id,
            turn_id=turn_id,
            agent_id=agent_id,
            planned_actions=planned_actions,
            serialized_decision=serialized,
        )
        return serialized
