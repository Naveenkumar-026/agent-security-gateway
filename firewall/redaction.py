from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass
from typing import Dict, List, Sequence

from .config import RedactionConfig


@dataclass(frozen=True)
class RedactionEvent:
    kind: str
    digest: str
    length: int


@dataclass(frozen=True)
class RedactionResult:
    sanitized_text: str
    events: List[RedactionEvent]

    @property
    def redacted(self) -> bool:
        return bool(self.events)


class OutputRedactor:
    _SECRET_KV = re.compile(
        r"(?i)\b(api[_-]?key|access[_-]?token|refresh[_-]?token|token|secret|password)\b(\s*[:=]\s*)([^\s,;]+)"
    )
    _JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,}\b")
    _AWS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
    _TOKEN_CANDIDATE = re.compile(r"\b[A-Za-z0-9_-]{20,}\b")
    _EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
    _PHONE = re.compile(r"(?<!\d)(?:\+?\d{1,2}[ -]?)?(?:\(?\d{3}\)?[ -]?)\d{3}[ -]?\d{4}(?!\d)")
    _SSN = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")

    def __init__(self, config: RedactionConfig) -> None:
        self.config = config

    @staticmethod
    def _digest(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()[:12]

    @staticmethod
    def _mask_token(kind: str, token: str) -> str:
        digest = OutputRedactor._digest(token)
        return f"[REDACTED:{kind}:{digest}]"

    @staticmethod
    def _shannon_entropy(text: str) -> float:
        if not text:
            return 0.0
        counts: Dict[str, int] = {}
        for ch in text:
            counts[ch] = counts.get(ch, 0) + 1
        length = len(text)
        entropy = 0.0
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def _looks_redacted(token: str) -> bool:
        return token.startswith("[REDACTED:") and token.endswith("]")

    def _event(self, kind: str, raw: str) -> RedactionEvent:
        return RedactionEvent(kind=kind, digest=self._digest(raw), length=len(raw))

    def _dedupe(self, events: Sequence[RedactionEvent]) -> List[RedactionEvent]:
        seen = set()
        out: List[RedactionEvent] = []
        for ev in events:
            key = (ev.kind, ev.digest)
            if key in seen:
                continue
            seen.add(key)
            out.append(ev)
            if len(out) >= self.config.max_masked_items_per_output:
                break
        return out

    def redact_text(self, text: str) -> RedactionResult:
        if not self.config.enabled or not text:
            return RedactionResult(sanitized_text=text, events=[])

        events: List[RedactionEvent] = []
        out = text

        def replace_secret_kv(match: re.Match[str]) -> str:
            key = match.group(1)
            sep = match.group(2)
            value = match.group(3)
            if self._looks_redacted(value):
                return match.group(0)
            events.append(self._event("secret", value))
            return f"{key}{sep}{self._mask_token('secret', value)}"

        out = self._SECRET_KV.sub(replace_secret_kv, out)

        def replace_direct(kind: str):
            def _repl(match: re.Match[str]) -> str:
                value = match.group(0)
                if self._looks_redacted(value):
                    return value
                events.append(self._event(kind, value))
                return self._mask_token(kind, value)

            return _repl

        out = self._JWT.sub(replace_direct("secret"), out)
        out = self._AWS_KEY.sub(replace_direct("secret"), out)

        def replace_entropy(match: re.Match[str]) -> str:
            value = match.group(0)
            if self._looks_redacted(value):
                return value
            if len(value) < self.config.high_entropy_min_length:
                return value
            if self._shannon_entropy(value) < self.config.high_entropy_min_entropy:
                return value
            events.append(self._event("high_entropy", value))
            return self._mask_token("high_entropy", value)

        out = self._TOKEN_CANDIDATE.sub(replace_entropy, out)

        if self.config.mask_pii:
            out = self._EMAIL.sub(replace_direct("pii_email"), out)
            out = self._PHONE.sub(replace_direct("pii_phone"), out)
            out = self._SSN.sub(replace_direct("pii_ssn"), out)

        deduped = self._dedupe(events)
        return RedactionResult(sanitized_text=out, events=deduped)
