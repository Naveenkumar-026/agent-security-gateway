from __future__ import annotations

import json
from typing import Any, Dict, List

from fastapi import APIRouter, Query, Request
from fastapi.responses import HTMLResponse

router = APIRouter(prefix="/operator", tags=["operator"])


def _to_script_json(payload: Dict[str, Any]) -> str:
    # Escape the closing script sequence so JSON can be embedded safely.
    return json.dumps(payload, ensure_ascii=True).replace("</", "<\\/")


def _render_dashboard(payload: Dict[str, Any]) -> str:
    return f"""<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\">
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
  <title>Agent Security Gateway Operator Console</title>
  <style>
    :root {{
      --bg: #f7f6f2;
      --card: #ffffff;
      --text: #1f2933;
      --muted: #57606a;
      --accent: #0f766e;
      --danger: #b91c1c;
      --warn: #b45309;
      --ok: #166534;
      --line: #d9e2ec;
      --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      --sans: "Segoe UI", Tahoma, Arial, sans-serif;
    }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; font-family: var(--sans); background: linear-gradient(180deg, #f9fafb 0%, var(--bg) 100%); color: var(--text); }}
    header {{ padding: 18px 20px; border-bottom: 1px solid var(--line); background: #fff; position: sticky; top: 0; }}
    main {{ padding: 16px; display: grid; grid-template-columns: repeat(12, 1fr); gap: 12px; }}
    .card {{ grid-column: span 12; border: 1px solid var(--line); background: var(--card); border-radius: 10px; padding: 12px; overflow: auto; }}
    .half {{ grid-column: span 6; }}
    h1 {{ margin: 0; font-size: 1.05rem; }}
    h2 {{ margin: 0 0 8px; font-size: 0.95rem; }}
    p, li {{ font-size: 0.9rem; line-height: 1.35; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
    th, td {{ padding: 6px; border-bottom: 1px solid #eef2f6; text-align: left; vertical-align: top; }}
    th {{ color: var(--muted); font-weight: 600; }}
    .decision-block {{ color: var(--danger); font-weight: 700; }}
    .decision-challenge, .decision-require_approval {{ color: var(--warn); font-weight: 700; }}
    .decision-allow {{ color: var(--ok); font-weight: 700; }}
    code {{ font-family: var(--mono); font-size: 0.82rem; }}
    details summary {{ cursor: pointer; color: var(--accent); font-weight: 600; }}
    @media (max-width: 980px) {{ .half {{ grid-column: span 12; }} }}
  </style>
</head>
<body>
<header>
  <h1>Agent Security Gateway Operator Console</h1>
</header>
<main>
  <section class=\"card half\">
    <h2>Recent Sessions</h2>
    <table id=\"sessions\"></table>
  </section>
  <section class=\"card half\">
    <h2>Approvals Queue</h2>
    <table id=\"approvals\"></table>
  </section>
  <section class=\"card\">
    <h2>Blocked/Challenged Events</h2>
    <table id=\"events\"></table>
  </section>
  <section class=\"card\">
    <h2>Session Timeline</h2>
    <p>Set query param <code>?session_id=&lt;id&gt;</code> to focus timeline.</p>
    <table id=\"timeline\"></table>
  </section>
</main>
<script>
const DATA = {_to_script_json(payload)};

function esc(v) {{
  return String(v ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#39;");
}}

function td(v) {{ return `<td>${{esc(v)}}</td>`; }}
function decisionCell(v) {{
  const c = `decision-${{String(v || '').toLowerCase()}}`;
  return `<td class="${{c}}">${{esc(v)}}</td>`;
}}

function reasonsCell(reasons) {{
  const joined = Array.isArray(reasons) ? reasons.join(' | ') : '';
  return `<td><details><summary>reasons</summary><code>${{esc(joined)}}</code></details></td>`;
}}

function fillSessions(rows) {{
  const el = document.getElementById("sessions");
  el.innerHTML = `<tr><th>Session</th><th>Agent</th><th>Req</th><th>Risk</th><th>Updated</th></tr>` + rows.map(r =>
    `<tr>${{td(r.session_id)}}${{td(r.agent_id)}}${{td(r.request_count)}}${{td(r.cumulative_risk)}}${{td(r.updated_at)}}</tr>`
  ).join("");
}}

function fillApprovals(rows) {{
  const el = document.getElementById("approvals");
  el.innerHTML = `<tr><th>Approval</th><th>Status</th><th>Session</th><th>Action</th><th>Expires</th></tr>` + rows.map(r =>
    `<tr>${{td(r.approval_id)}}${{decisionCell(r.status)}}${{td(r.session_id)}}${{td(`${{r.action_type}}:${{r.action_target}}`)}}${{td(r.expires_at)}}</tr>`
  ).join("");
}}

function fillEvents(rows, tableId) {{
  const el = document.getElementById(tableId);
  el.innerHTML = `<tr><th>Time</th><th>Session</th><th>Decision</th><th>Action</th><th>Score</th><th>Details</th></tr>` + rows.map(r =>
    `<tr>${{td(r.created_at)}}${{td(r.session_id)}}${{decisionCell(r.decision)}}${{td(`${{r.action_type}}:${{r.action_target}}`)}}${{td(r.total_score)}}${{reasonsCell(r.reasons)}}</tr>`
  ).join("");
}}

fillSessions(DATA.sessions || []);
fillApprovals(DATA.approvals_pending || []);
fillEvents(DATA.events_flagged || [], "events");
fillEvents(DATA.timeline || [], "timeline");
</script>
</body>
</html>"""


@router.get("", response_class=HTMLResponse)
def operator_console(
    request: Request,
    session_id: str = Query(default="", min_length=0, max_length=256),
    limit: int = Query(default=50, ge=1, le=200),
) -> HTMLResponse:
    service = request.app.state.gateway_service
    selected_session = session_id.strip()
    sessions = service.list_recent_sessions(limit=limit)
    pending = service.list_pending_approvals(limit=limit)
    flagged = service.list_recent_events(limit=limit, only_flagged=True)
    timeline: List[Dict[str, Any]] = service.get_session_timeline(selected_session, limit=limit) if selected_session else []

    payload = {
        "sessions": sessions,
        "approvals_pending": pending,
        "events_flagged": flagged,
        "timeline": timeline,
        "selected_session": selected_session,
    }
    return HTMLResponse(_render_dashboard(payload))


@router.get("/api/overview")
def operator_overview(
    request: Request,
    session_id: str = Query(default="", min_length=0, max_length=256),
    limit: int = Query(default=50, ge=1, le=200),
) -> Dict[str, Any]:
    service = request.app.state.gateway_service
    selected_session = session_id.strip()
    payload: Dict[str, Any] = {
        "sessions": service.list_recent_sessions(limit=limit),
        "approvals_pending": service.list_pending_approvals(limit=limit),
        "approvals_recent": service.list_recent_approvals(limit=limit),
        "events_flagged": service.list_recent_events(limit=limit, only_flagged=True),
        "selected_session": selected_session,
        "timeline": [],
    }
    if selected_session:
        payload["timeline"] = service.get_session_timeline(selected_session, limit=limit)
    return payload


@router.get("/api/session/{session_id}/timeline")
def operator_session_timeline(
    session_id: str,
    request: Request,
    limit: int = Query(default=200, ge=1, le=500),
) -> Dict[str, Any]:
    service = request.app.state.gateway_service
    return {
        "session_id": session_id,
        "timeline": service.get_session_timeline(session_id=session_id, limit=limit),
    }
