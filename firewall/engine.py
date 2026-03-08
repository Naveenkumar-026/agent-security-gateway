from __future__ import annotations

from dataclasses import asdict
from typing import Any, Dict, List, Optional

from .chain_guard import ActionChainGuard
from .config import FirewallConfig, load_config
from .detectors import Detector, build_detectors
from .logging_utils import get_logger
from .policy import PolicyEngine
from .types import Decision, Finding, SecurityContext


class SecurityFirewall:
    def __init__(self, config: Optional[FirewallConfig] = None, config_path: Optional[str] = None) -> None:
        self.config = config or load_config(config_path=config_path)
        self.detectors: List[Detector] = build_detectors(self.config)
        self.chain_guard = ActionChainGuard(list(self.config.chain_rules))
        self.policy = PolicyEngine(self.config.policy)
        self.logger = get_logger(
            name="firewall",
            level=self.config.logging.level,
            structured=self.config.logging.structured,
        )

    @staticmethod
    def _mask_value(value: str) -> str:
        text = value.strip()
        if not text:
            return ""
        if len(text) <= 6:
            return "***"
        return f"{text[:3]}***{text[-3:]}"

    def _sanitize_for_logs(self, value: Any) -> Any:
        if isinstance(value, dict):
            return {str(k): self._sanitize_for_logs(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self._sanitize_for_logs(v) for v in value]
        if isinstance(value, str):
            if not self.config.logging.redact_sensitive:
                return value
            return self._mask_value(value)
        return value

    def _sanitize_findings_for_logs(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        serialized = [asdict(finding) for finding in findings]
        if not self.config.logging.redact_sensitive:
            return serialized

        sanitized: List[Dict[str, Any]] = []
        for item in serialized:
            metadata = item.get("metadata", {})
            if isinstance(metadata, dict):
                for key in ("target", "chain"):
                    if key in metadata and isinstance(metadata[key], str):
                        metadata[key] = self._mask_value(metadata[key])
            sanitized.append(item)
        return sanitized

    def inspect(self, ctx: SecurityContext) -> Decision:
        findings: List[Finding] = []
        triggered_detectors: List[str] = []

        for detector in self.detectors:
            detector_findings = detector.detect(ctx)
            if detector_findings:
                triggered_detectors.append(detector.name)
                findings.extend(detector_findings)

        if self.config.detector_toggles.get("unsafe_action_chain", True):
            chain_findings = self.chain_guard.analyze(ctx)
            if chain_findings:
                triggered_detectors.append("unsafe_action_chain")
                findings.extend(chain_findings)

        metadata: Dict[str, Any] = {
            "triggered_detectors": sorted(set(triggered_detectors)),
            "planned_actions": [f"{a.action_type}:{a.target}" for a in ctx.planned_actions],
            "memory_reads": list(ctx.memory_reads),
            "memory_writes": list(ctx.memory_writes),
        }

        decision = self.policy.evaluate(findings=findings, request_id=ctx.request_id, metadata=metadata)
        self._audit_log(ctx, decision)
        return decision

    def _audit_log(self, ctx: SecurityContext, decision: Decision) -> None:
        log_metadata = self._sanitize_for_logs(decision.metadata)
        self.logger.info(
            "firewall_decision",
            extra={
                "extra_fields": {
                    "event": "firewall_decision",
                    "request_id": ctx.request_id,
                    "context_created_at": ctx.created_at,
                    "decision": decision.decision,
                    "total_score": decision.total_score,
                    "reason_count": len(decision.reasons),
                    "reasons": decision.reasons,
                    "findings": self._sanitize_findings_for_logs(decision.findings),
                    "metadata": log_metadata,
                    "decided_at": decision.decided_at,
                }
            },
        )