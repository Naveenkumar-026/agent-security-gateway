from __future__ import annotations

from typing import List, Sequence

from .config import ChainRuleConfig
from .types import Finding, SecurityContext


class ActionChainGuard:
    """Detects unsafe combinations of actions.

    Trust boundary: this operates on declared/planned actions from upstream runtimes.
    If plans are incomplete or obfuscated, this guard cannot ensure full safety.
    """

    def __init__(self, rules: List[ChainRuleConfig]) -> None:
        self.rules = rules

    @staticmethod
    def _is_ordered_subsequence(required: Sequence[str], observed: Sequence[str]) -> bool:
        idx = 0
        for action in observed:
            if action == required[idx]:
                idx += 1
                if idx == len(required):
                    return True
        return False

    def analyze(self, ctx: SecurityContext) -> List[Finding]:
        findings: List[Finding] = []
        observed_actions = [a.action_type for a in ctx.planned_actions]
        observed_set = set(observed_actions)
        chain = [f"{a.action_type}:{a.target}" for a in ctx.planned_actions]
        joined = " -> ".join(chain)

        for rule in self.rules:
            if rule.ordered:
                matched = self._is_ordered_subsequence(rule.required_actions, observed_actions)
            else:
                matched = all(required in observed_set for required in rule.required_actions)

            if matched:
                findings.append(
                    Finding(
                        category="unsafe_action_chain",
                        severity=rule.severity,
                        score=rule.score,
                        message=rule.message,
                        detector="unsafe_action_chain",
                        metadata={
                            "rule": rule.name,
                            "ordered": str(rule.ordered).lower(),
                            "required_actions": ",".join(rule.required_actions),
                            "chain": joined,
                        },
                    )
                )
        return findings