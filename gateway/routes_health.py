from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Request
from fastapi.responses import PlainTextResponse

from firewall.models import HealthResponse

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(status="ok")


@router.get("/ready")
def ready(request: Request) -> Dict[str, Any]:
    app_state = request.app.state
    details: Dict[str, bool] = {
        "session_store": bool(app_state.session_store.ping()),
        "approval_store": bool(app_state.approval_store.ping()),
        "audit_store": bool(app_state.audit_store.ping()),
    }

    runtime_config = getattr(app_state, "runtime_config", None)
    if runtime_config is not None and runtime_config.auth_enabled:
        details["auth_configured"] = bool(runtime_config.api_keys)

    ready_ok = all(details.values())
    return {"status": "ready" if ready_ok else "not_ready", "details": details}


@router.get("/metrics", response_class=PlainTextResponse)
def metrics(request: Request) -> PlainTextResponse:
    payload = request.app.state.metrics.render_prometheus()
    return PlainTextResponse(payload, media_type="text/plain; version=0.0.4")
