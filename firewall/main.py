from __future__ import annotations

import argparse
import json
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any, Dict, List

from .config import load_config
from .engine import SecurityFirewall
from .types import Decision, PlannedAction, SecurityContext

_ALLOWED_INPUT_KEYS = {"user_input", "model_output", "planned_actions", "memory_reads", "memory_writes"}
_MAX_TEXT_LEN = 50000
_MAX_COLLECTION_ITEMS = 256
_MAX_ITEM_LEN = 2048


def parse_action(raw: str) -> PlannedAction:
    text = raw.strip()
    if not text:
        raise ValueError("planned action cannot be empty")
    if ":" not in text:
        return PlannedAction(action_type=text, target="")
    action_type, target = text.split(":", 1)
    action_type = action_type.strip()
    if not action_type:
        raise ValueError("planned action_type cannot be empty")
    return PlannedAction(action_type=action_type, target=target.strip())


def _read_json_payload(path: str) -> Dict[str, Any]:
    if path == "-":
        data = json.load(sys.stdin)
    else:
        with Path(path).open("r", encoding="utf-8") as f:
            data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("JSON input must be an object")
    unknown_keys = sorted(set(data.keys()) - _ALLOWED_INPUT_KEYS)
    if unknown_keys:
        raise ValueError(f"Unexpected JSON keys: {unknown_keys}")
    return data


def _coerce_str_list(name: str, value: Any) -> List[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(f"{name} must be a list of strings")
    if len(value) > _MAX_COLLECTION_ITEMS:
        raise ValueError(f"{name} exceeds max items ({_MAX_COLLECTION_ITEMS})")

    result = [str(v) for v in value]
    for item in result:
        if len(item) > _MAX_ITEM_LEN:
            raise ValueError(f"{name} entry exceeds max length ({_MAX_ITEM_LEN})")
    return result


def _validate_context(ctx: SecurityContext) -> None:
    if len(ctx.user_input) > _MAX_TEXT_LEN:
        raise ValueError(f"user_input exceeds max length ({_MAX_TEXT_LEN})")
    if len(ctx.model_output) > _MAX_TEXT_LEN:
        raise ValueError(f"model_output exceeds max length ({_MAX_TEXT_LEN})")
    if len(ctx.planned_actions) > _MAX_COLLECTION_ITEMS:
        raise ValueError(f"planned_actions exceeds max items ({_MAX_COLLECTION_ITEMS})")


def _payload_to_context(payload: Dict[str, Any]) -> SecurityContext:
    planned_raw = payload.get("planned_actions")
    if planned_raw is None:
        planned_raw = []
    if not isinstance(planned_raw, list):
        raise ValueError("planned_actions must be a list")
    if len(planned_raw) > _MAX_COLLECTION_ITEMS:
        raise ValueError(f"planned_actions exceeds max items ({_MAX_COLLECTION_ITEMS})")

    planned_actions: List[PlannedAction] = []
    for item in planned_raw:
        if isinstance(item, str):
            planned_actions.append(parse_action(item))
        elif isinstance(item, dict):
            planned_actions.append(
                PlannedAction(
                    action_type=str(item.get("action_type", "")).strip(),
                    target=str(item.get("target", "")).strip(),
                )
            )
        else:
            raise ValueError("planned_actions entries must be strings or objects")

    ctx = SecurityContext(
        user_input=str(payload.get("user_input", "")),
        model_output=str(payload.get("model_output", "")),
        memory_reads=_coerce_str_list("memory_reads", payload.get("memory_reads")),
        memory_writes=_coerce_str_list("memory_writes", payload.get("memory_writes")),
        planned_actions=planned_actions,
    )
    _validate_context(ctx)
    return ctx


def _decision_to_json(decision: Decision) -> Dict[str, Any]:
    return {
        "decision": decision.decision,
        "total_score": decision.total_score,
        "findings": [
            {
                "category": f.category,
                "severity": f.severity,
                "score": f.score,
                "message": f.message,
                "detector": f.detector,
                "metadata": dict(f.metadata),
            }
            for f in decision.findings
        ],
        "reasons": list(decision.reasons),
        "request_id": decision.request_id,
        "decided_at": decision.decided_at,
        "metadata": dict(decision.metadata),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="AI Agent Security Firewall CLI",
        epilog=(
            "Examples:\n"
            "  python -m firewall.main --user-input \"Summarize this\"\n"
            "  python -m firewall.main --input-json request.json\n"
            "  python -m firewall.main --planned-action exec_shell:dir --memory-read system"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("--config", help="Path to JSON config file", default=None)
    parser.add_argument("--input-json", help="Path to JSON request file, or '-' for stdin", default=None)

    parser.add_argument("--user-input", default="", help="User prompt text")
    parser.add_argument("--model-output", default="", help="Model output text")
    parser.add_argument("--planned-action", action="append", default=[], help="Action in action_type:target format")
    parser.add_argument("--memory-read", action="append", default=[], help="Memory read key/path")
    parser.add_argument("--memory-write", action="append", default=[], help="Memory write key/path")

    parser.add_argument("--pretty", action="store_true", help="Pretty-print output JSON")
    parser.add_argument(
        "--decision-exit-codes",
        action="store_true",
        help="Return exit code 10 for challenge and 20 for block",
    )
    parser.add_argument(
        "--log-level",
        choices=["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"],
        default="ERROR",
        help="CLI logger level (defaults to ERROR to keep stdout clean)",
    )
    return parser


def _context_from_args(args: argparse.Namespace) -> SecurityContext:
    if args.input_json:
        has_inline_data = bool(
            args.user_input.strip()
            or args.model_output.strip()
            or args.planned_action
            or args.memory_read
            or args.memory_write
        )
        if has_inline_data:
            raise ValueError("--input-json cannot be combined with inline context flags")
        payload = _read_json_payload(args.input_json)
        return _payload_to_context(payload)

    planned_actions = [parse_action(raw) for raw in args.planned_action]
    ctx = SecurityContext(
        user_input=args.user_input,
        model_output=args.model_output,
        planned_actions=planned_actions,
        memory_reads=list(args.memory_read),
        memory_writes=list(args.memory_write),
    )
    _validate_context(ctx)
    return ctx


def main(argv: List[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        cfg = load_config(config_path=args.config)
        cfg = replace(cfg, logging=replace(cfg.logging, level=args.log_level))
        firewall = SecurityFirewall(config=cfg)

        ctx = _context_from_args(args)
        decision = firewall.inspect(ctx)

        output = _decision_to_json(decision)
        if args.pretty:
            print(json.dumps(output, indent=2))
        else:
            print(json.dumps(output, separators=(",", ":")))

        if args.decision_exit_codes:
            if decision.decision == "challenge":
                return 10
            if decision.decision == "block":
                return 20
        return 0
    except (ValueError, json.JSONDecodeError) as exc:
        parser.exit(status=2, message=f"error: {exc}\n")
        return 2
    except OSError as exc:
        parser.exit(status=2, message=f"error: {exc}\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
