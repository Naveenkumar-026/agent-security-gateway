from __future__ import annotations

from collections import Counter, defaultdict
from typing import Dict, List, Tuple

from .config import PolicyConfig
from .types import Decision, Finding


class PolicyEngine:
    def __init__(self, config: PolicyConfig) -> None:
        self.config = config

    @staticmethod
    def _dedupe_findings(findings: List[Finding]) -> List[Finding]:
        seen: set[Tuple[str, str, str, str]] = set()
        deduped: List[Finding] = []
        for finding in findings:
            key = (finding.detector, finding.category, finding.severity, finding.message)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(finding)
        return deduped

    def evaluate(self, findings: List[Finding], request_id: str, metadata: dict | None = None) -> Decision:
        if not findings:
            return Decision(
                decision="allow",
                total_score=0.0,
                findings=[],
                reasons=["No security findings detected."],
                request_id=request_id,
                metadata=metadata or {},
            )

        effective_findings = self._dedupe_findings(findings)
        severity_counts = Counter(f.severity for f in effective_findings)
        detector_counts = Counter(f.detector for f in effective_findings)

        detector_totals: Dict[str, float] = defaultdict(float)
        for finding in effective_findings:
            detector_totals[finding.detector] += finding.score

        capped_detector_totals = {
            detector: min(total, self.config.detector_score_cap)
            for detector, total in detector_totals.items()
        }
        total = sum(capped_detector_totals.values())

        critical_count = severity_counts.get("critical", 0)
        high_count = severity_counts.get("high", 0)
        flood_detectors = [
            detector
            for detector, count in detector_counts.items()
            if count > self.config.max_findings_per_detector
        ]

        reasons: List[str] = []
        if critical_count:
            reasons.append(f"Critical findings present ({critical_count}).")
        if high_count >= self.config.block_high_count:
            reasons.append(f"High-severity findings exceed threshold ({high_count}).")
        if total >= self.config.block_score:
            reasons.append(f"Risk score too high ({total:.2f}).")
        if flood_detectors:
            reasons.append(f"Detector finding flood detected: {sorted(flood_detectors)}")

        eval_metadata = dict(metadata or {})
        eval_metadata.update(
            {
                "detector_totals": detector_totals,
                "capped_detector_totals": capped_detector_totals,
                "deduped_finding_count": len(effective_findings),
            }
        )

        should_block = (
            (self.config.block_if_critical and critical_count > 0)
            or high_count >= self.config.block_high_count
            or total >= self.config.block_score
            or bool(flood_detectors)
        )
        if should_block:
            return Decision(
                decision="block",
                total_score=total,
                findings=effective_findings,
                reasons=reasons,
                request_id=request_id,
                metadata=eval_metadata,
            )

        if high_count > 0 or total >= self.config.challenge_score:
            reasons.append("Elevated risk requires additional approval.")
            return Decision(
                decision="challenge",
                total_score=total,
                findings=effective_findings,
                reasons=reasons,
                request_id=request_id,
                metadata=eval_metadata,
            )

        reasons.append("Low risk, proceed with monitoring.")
        return Decision(
            decision="allow",
            total_score=total,
            findings=effective_findings,
            reasons=reasons,
            request_id=request_id,
            metadata=eval_metadata,
        )