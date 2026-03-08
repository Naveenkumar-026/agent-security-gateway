from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional
from urllib import error, request


@dataclass(frozen=True)
class GatewayClientError(Exception):
    message: str
    status_code: int
    payload: Optional[Dict[str, Any]] = None

    def __str__(self) -> str:
        return f"{self.status_code}: {self.message}"


class GatewayClient:
    def __init__(self, base_url: str = "http://127.0.0.1:8000", timeout_seconds: float = 5.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds

    def _post_json(self, path: str, payload: Mapping[str, Any]) -> Dict[str, Any]:
        data = json.dumps(dict(payload)).encode("utf-8")
        req = request.Request(
            url=f"{self.base_url}{path}",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        return self._perform_request(req)

    def _get_json(self, path: str) -> Dict[str, Any]:
        req = request.Request(url=f"{self.base_url}{path}", method="GET")
        return self._perform_request(req)

    def _perform_request(self, req: request.Request) -> Dict[str, Any]:
        try:
            with request.urlopen(req, timeout=self.timeout_seconds) as resp:
                body = resp.read().decode("utf-8")
                return json.loads(body)
        except error.HTTPError as exc:
            raw = exc.read().decode("utf-8") if exc.fp is not None else ""
            payload: Optional[Dict[str, Any]]
            try:
                payload = json.loads(raw) if raw else None
            except json.JSONDecodeError:
                payload = None
            message = payload.get("error", exc.reason) if isinstance(payload, dict) else str(exc.reason)
            raise GatewayClientError(message=message, status_code=exc.code, payload=payload) from exc
        except error.URLError as exc:
            raise GatewayClientError(message=str(exc.reason), status_code=0, payload=None) from exc

    def health(self) -> Dict[str, Any]:
        return self._get_json("/health")

    def inspect_input(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        return self._post_json("/inspect/input", payload)

    def inspect_tool_call(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        return self._post_json("/inspect/tool-call", payload)
