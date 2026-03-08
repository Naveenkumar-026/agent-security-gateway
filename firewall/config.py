from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Mapping, MutableMapping, Optional, Tuple, cast

from .types import Severity

_ALLOWED_SEVERITIES: Tuple[Severity, ...] = ("low", "medium", "high", "critical")
_KNOWN_DETECTORS: Tuple[str, ...] = (
    "prompt_injection",
    "secret_leakage",
    "tool_abuse",
    "policy_drift",
    "unsafe_action_chain",
)


@dataclass(frozen=True)
class PolicyConfig:
    block_score: float = 1.8
    challenge_score: float = 0.9
    block_high_count: int = 2
    block_if_critical: bool = True
    detector_score_cap: float = 1.5
    max_findings_per_detector: int = 8
    allow_with_redaction: bool = True

    def validate(self) -> None:
        if self.block_score <= 0:
            raise ValueError("policy.block_score must be > 0")
        if self.challenge_score < 0:
            raise ValueError("policy.challenge_score must be >= 0")
        if self.challenge_score > self.block_score:
            raise ValueError("policy.challenge_score cannot exceed policy.block_score")
        if self.block_high_count < 1:
            raise ValueError("policy.block_high_count must be >= 1")
        if self.detector_score_cap <= 0:
            raise ValueError("policy.detector_score_cap must be > 0")
        if self.max_findings_per_detector < 1:
            raise ValueError("policy.max_findings_per_detector must be >= 1")
        if not isinstance(self.allow_with_redaction, bool):
            raise ValueError("policy.allow_with_redaction must be a boolean")


@dataclass(frozen=True)
class LoggingConfig:
    level: str = "INFO"
    structured: bool = True
    redact_sensitive: bool = True

    def validate(self) -> None:
        valid = {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"}
        if self.level.upper() not in valid:
            raise ValueError(f"logging.level must be one of {sorted(valid)}")


@dataclass(frozen=True)
class RedactionConfig:
    enabled: bool = True
    mask_pii: bool = True
    high_entropy_min_entropy: float = 3.7
    high_entropy_min_length: int = 20
    max_masked_items_per_output: int = 32

    def validate(self) -> None:
        if not isinstance(self.enabled, bool):
            raise ValueError("redaction.enabled must be a boolean")
        if not isinstance(self.mask_pii, bool):
            raise ValueError("redaction.mask_pii must be a boolean")
        if self.high_entropy_min_entropy <= 0:
            raise ValueError("redaction.high_entropy_min_entropy must be > 0")
        if self.high_entropy_min_length < 8:
            raise ValueError("redaction.high_entropy_min_length must be >= 8")
        if self.max_masked_items_per_output < 1:
            raise ValueError("redaction.max_masked_items_per_output must be >= 1")


@dataclass(frozen=True)
class ChainRuleConfig:
    name: str
    required_actions: Tuple[str, ...]
    ordered: bool
    severity: Severity
    score: float
    message: str

    def validate(self) -> None:
        if not self.name.strip():
            raise ValueError("chain rule name cannot be empty")
        if len(self.required_actions) < 2:
            raise ValueError("chain rule must include at least two required actions")
        if any(not action.strip() for action in self.required_actions):
            raise ValueError("chain rule actions cannot be empty")
        if self.severity not in _ALLOWED_SEVERITIES:
            raise ValueError(f"chain rule severity must be one of {_ALLOWED_SEVERITIES}")
        if self.score < 0:
            raise ValueError("chain rule score must be >= 0")


@dataclass(frozen=True)
class FirewallConfig:
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    redaction: RedactionConfig = field(default_factory=RedactionConfig)
    detector_toggles: Mapping[str, bool] = field(
        default_factory=lambda: {
            "prompt_injection": True,
            "secret_leakage": True,
            "tool_abuse": True,
            "policy_drift": True,
            "unsafe_action_chain": True,
        }
    )
    sensitive_actions: Mapping[str, Tuple[Severity, float]] = field(
        default_factory=lambda: {
            "exec_shell": ("high", 0.7),
            "write_filesystem": ("medium", 0.45),
            "network_exfiltration": ("critical", 0.95),
            "permission_escalation": ("critical", 1.0),
        }
    )
    chain_rules: Tuple[ChainRuleConfig, ...] = field(
        default_factory=lambda: (
            ChainRuleConfig(
                name="memory_plus_network",
                required_actions=("read_memory", "network_exfiltration"),
                ordered=True,
                severity="critical",
                score=0.95,
                message="Memory read followed by network path may exfiltrate sensitive data.",
            ),
            ChainRuleConfig(
                name="shell_plus_privilege_escalation",
                required_actions=("exec_shell", "permission_escalation"),
                ordered=False,
                severity="critical",
                score=1.0,
                message="Shell execution plus privilege escalation detected.",
            ),
            ChainRuleConfig(
                name="shell_plus_network",
                required_actions=("exec_shell", "network_exfiltration"),
                ordered=False,
                severity="high",
                score=0.75,
                message="Shell + network combination requires review.",
            ),
            ChainRuleConfig(
                name="memory_plus_shell",
                required_actions=("read_memory", "exec_shell"),
                ordered=True,
                severity="high",
                score=0.7,
                message="Memory read followed by shell execution is high risk.",
            ),
        )
    )

    def validate(self) -> None:
        self.policy.validate()
        self.logging.validate()
        self.redaction.validate()
        if not self.detector_toggles:
            raise ValueError("detector_toggles cannot be empty")
        unknown_detector_toggles = set(self.detector_toggles) - set(_KNOWN_DETECTORS)
        if unknown_detector_toggles:
            raise ValueError(f"unknown detector toggles: {sorted(unknown_detector_toggles)}")
        for action_name, (severity, score) in self.sensitive_actions.items():
            if not action_name.strip():
                raise ValueError("sensitive action name cannot be empty")
            if severity not in _ALLOWED_SEVERITIES:
                raise ValueError(f"sensitive action severity must be one of {_ALLOWED_SEVERITIES}")
            if score < 0:
                raise ValueError("sensitive action score must be >= 0")
        for rule in self.chain_rules:
            rule.validate()


_ENV_BOOL_TRUE = {"1", "true", "yes", "on"}
_ENV_BOOL_FALSE = {"0", "false", "no", "off"}


def _parse_env_bool(value: str) -> bool:
    lowered = value.strip().lower()
    if lowered in _ENV_BOOL_TRUE:
        return True
    if lowered in _ENV_BOOL_FALSE:
        return False
    raise ValueError(f"Invalid boolean value: {value}")


def _load_json_file(path: Path) -> MutableMapping[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        raw = json.load(f)
    if not isinstance(raw, dict):
        raise ValueError("Config file must contain a top-level JSON object")
    return raw


def _merge(base: MutableMapping[str, Any], updates: Mapping[str, Any]) -> MutableMapping[str, Any]:
    for key, value in updates.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _merge(cast(MutableMapping[str, Any], base[key]), value)
        else:
            base[key] = value
    return base


def _coerce_sensitive_actions(raw: Mapping[str, Any]) -> Dict[str, Tuple[Severity, float]]:
    coerced: Dict[str, Tuple[Severity, float]] = {}
    for action, payload in raw.items():
        if not isinstance(payload, (list, tuple)) or len(payload) != 2:
            raise ValueError(f"sensitive_actions.{action} must be [severity, score]")
        severity_raw, score_raw = payload
        severity = str(severity_raw).lower()
        if severity not in _ALLOWED_SEVERITIES:
            raise ValueError(f"sensitive_actions.{action}.severity must be one of {_ALLOWED_SEVERITIES}")
        coerced[str(action).strip().lower()] = (cast(Severity, severity), float(score_raw))
    return coerced


def _default_chain_rules_payload() -> list[dict[str, Any]]:
    return [
        {
            "name": r.name,
            "required_actions": list(r.required_actions),
            "ordered": r.ordered,
            "severity": r.severity,
            "score": r.score,
            "message": r.message,
        }
        for r in FirewallConfig().chain_rules
    ]


def load_config(config_path: Optional[str] = None, env: Optional[Mapping[str, str]] = None) -> FirewallConfig:
    data: MutableMapping[str, Any] = {}
    if config_path:
        data = _load_json_file(Path(config_path))

    env_map = env if env is not None else os.environ
    env_overrides: Dict[str, Any] = {"policy": {}, "logging": {}, "redaction": {}, "detector_toggles": {}}

    if "FIREWALL_BLOCK_SCORE" in env_map:
        env_overrides["policy"]["block_score"] = float(env_map["FIREWALL_BLOCK_SCORE"])
    if "FIREWALL_CHALLENGE_SCORE" in env_map:
        env_overrides["policy"]["challenge_score"] = float(env_map["FIREWALL_CHALLENGE_SCORE"])
    if "FIREWALL_BLOCK_HIGH_COUNT" in env_map:
        env_overrides["policy"]["block_high_count"] = int(env_map["FIREWALL_BLOCK_HIGH_COUNT"])
    if "FIREWALL_BLOCK_IF_CRITICAL" in env_map:
        env_overrides["policy"]["block_if_critical"] = _parse_env_bool(env_map["FIREWALL_BLOCK_IF_CRITICAL"])
    if "FIREWALL_DETECTOR_SCORE_CAP" in env_map:
        env_overrides["policy"]["detector_score_cap"] = float(env_map["FIREWALL_DETECTOR_SCORE_CAP"])
    if "FIREWALL_MAX_FINDINGS_PER_DETECTOR" in env_map:
        env_overrides["policy"]["max_findings_per_detector"] = int(env_map["FIREWALL_MAX_FINDINGS_PER_DETECTOR"])
    if "FIREWALL_ALLOW_WITH_REDACTION" in env_map:
        env_overrides["policy"]["allow_with_redaction"] = _parse_env_bool(env_map["FIREWALL_ALLOW_WITH_REDACTION"])

    if "FIREWALL_LOG_LEVEL" in env_map:
        env_overrides["logging"]["level"] = env_map["FIREWALL_LOG_LEVEL"].upper()
    if "FIREWALL_STRUCTURED_LOGS" in env_map:
        env_overrides["logging"]["structured"] = _parse_env_bool(env_map["FIREWALL_STRUCTURED_LOGS"])
    if "FIREWALL_REDACT_LOGS" in env_map:
        env_overrides["logging"]["redact_sensitive"] = _parse_env_bool(env_map["FIREWALL_REDACT_LOGS"])

    if "FIREWALL_REDACTION_ENABLED" in env_map:
        env_overrides["redaction"]["enabled"] = _parse_env_bool(env_map["FIREWALL_REDACTION_ENABLED"])
    if "FIREWALL_REDACTION_MASK_PII" in env_map:
        env_overrides["redaction"]["mask_pii"] = _parse_env_bool(env_map["FIREWALL_REDACTION_MASK_PII"])
    if "FIREWALL_REDACTION_MIN_ENTROPY" in env_map:
        env_overrides["redaction"]["high_entropy_min_entropy"] = float(env_map["FIREWALL_REDACTION_MIN_ENTROPY"])
    if "FIREWALL_REDACTION_MIN_LENGTH" in env_map:
        env_overrides["redaction"]["high_entropy_min_length"] = int(env_map["FIREWALL_REDACTION_MIN_LENGTH"])
    if "FIREWALL_REDACTION_MAX_ITEMS" in env_map:
        env_overrides["redaction"]["max_masked_items_per_output"] = int(env_map["FIREWALL_REDACTION_MAX_ITEMS"])

    detector_env_map = {
        "FIREWALL_ENABLE_PROMPT_INJECTION": "prompt_injection",
        "FIREWALL_ENABLE_SECRET_LEAKAGE": "secret_leakage",
        "FIREWALL_ENABLE_TOOL_ABUSE": "tool_abuse",
        "FIREWALL_ENABLE_POLICY_DRIFT": "policy_drift",
        "FIREWALL_ENABLE_UNSAFE_CHAIN": "unsafe_action_chain",
    }
    for env_key, detector_key in detector_env_map.items():
        if env_key in env_map:
            env_overrides["detector_toggles"][detector_key] = _parse_env_bool(env_map[env_key])

    if "FIREWALL_SENSITIVE_ACTIONS_JSON" in env_map:
        parsed = json.loads(env_map["FIREWALL_SENSITIVE_ACTIONS_JSON"])
        if not isinstance(parsed, dict):
            raise ValueError("FIREWALL_SENSITIVE_ACTIONS_JSON must be a JSON object")
        env_overrides["sensitive_actions"] = parsed

    merged = _merge(data, env_overrides)

    default_cfg = FirewallConfig()
    rule_payloads = merged.get("chain_rules", _default_chain_rules_payload())
    if not isinstance(rule_payloads, list):
        raise ValueError("chain_rules must be an array")

    chain_rules: list[ChainRuleConfig] = []
    for idx, rule in enumerate(rule_payloads):
        if not isinstance(rule, dict):
            raise ValueError(f"chain_rules[{idx}] must be an object")
        if "required_actions" not in rule or not isinstance(rule["required_actions"], list):
            raise ValueError(f"chain_rules[{idx}].required_actions must be an array")
        chain_rules.append(
            ChainRuleConfig(
                name=str(rule.get("name", "")),
                required_actions=tuple(str(x).strip().lower() for x in rule["required_actions"]),
                ordered=bool(rule.get("ordered", False)),
                severity=cast(Severity, str(rule.get("severity", "")).lower()),
                score=float(rule.get("score", 0.0)),
                message=str(rule.get("message", "")),
            )
        )

    cfg = FirewallConfig(
        policy=PolicyConfig(**merged.get("policy", {})),
        logging=LoggingConfig(**merged.get("logging", {})),
        redaction=RedactionConfig(**merged.get("redaction", {})),
        detector_toggles={**default_cfg.detector_toggles, **merged.get("detector_toggles", {})},
        sensitive_actions=(
            _coerce_sensitive_actions(merged["sensitive_actions"])
            if "sensitive_actions" in merged
            else default_cfg.sensitive_actions
        ),
        chain_rules=tuple(chain_rules),
    )
    cfg.validate()
    return cfg
