# AI Agent Security Firewall + Agent Security Gateway

Security control that sits between agent intent/planning and real side effects (tool calls, API requests, memory access, filesystem/network actions).

## What This Repo Provides

- `firewall` library: deterministic detectors, chain guard, policy engine.
- `gateway` HTTP service over existing firewall/session/approval/redaction logic.
- Session-aware risk state and approval workflow.
- Central redaction/sanitization pipeline for model-visible/tool-returned outputs.
- Operator console and audit timeline APIs.
- Gateway hardening controls: explicit auth, deterministic rate limiting, metrics, health/readiness split.

## Single Enforcement Path

- Adapters do not embed independent policy engines.
- Approval and redaction decisions are evaluated in `GatewayInspectionService`.
- Auth/rate-limit/metrics controls live in gateway middleware, not adapters.

## API Surface

### Liveness / readiness / metrics
- `GET /health`: process alive.
- `GET /ready`: dependency readiness (`session_store`, `approval_store`, `audit_store`, auth config).
- `GET /metrics`: Prometheus-style counters.

### Inspection / approval
- `POST /inspect/input`
- `POST /inspect/tool-call`
- `POST /approval/submit`
- `POST /approval/resolve`

### Operator visibility
- `GET /operator`
- `GET /operator/api/overview`
- `GET /operator/api/session/{session_id}/timeline`

## Decision Semantics

- `block`: deny execution.
- `challenge` / `require_approval`: execution paused pending approval.
- `allow`: allowed without masking.
- `allow_with_redaction`: allowed, but central redaction pipeline masked output.

`allow_with_redaction` never downgrades a real block.

## Redaction Pipeline (Central)

1. Adapter executes only after pre-inspection allow.
2. Tool output passes to `GatewayInspectionService.sanitize_output(...)`.
3. Sanitized output (not raw) is returned and used in post-inspection.
4. Redaction metadata is attached to decision/audit (`kind`, digest prefix, length, count).

Masking support:
- secret key/value forms (`api_key=...`, `token=...`, etc.)
- JWT-like and AWS-key-like patterns
- high-entropy token masking
- optional PII masking (email/phone/SSN)

Deterministic token format:
- `[REDACTED:<kind>:<sha256-prefix>]`

## Gateway Hardening Controls (Phase 7)

### Auth (gateway layer)
- Optional API-key auth via middleware.
- Header name and keys configurable.
- Fail-closed when enabled and key missing/invalid.

### Rate limiting (gateway layer)
- Deterministic fixed-window limiter.
- Keyed by API key (if present) else client host.
- Returns `429` on exceed; resets by window boundary.

### Metrics
- Request counter: `gateway_http_requests_total{method,path,status}`
- Internal events: `gateway_events_total{name}`

## Environment Configuration

### Firewall/redaction
- `FIREWALL_CONFIG`
- `FIREWALL_SESSION_DB`
- `FIREWALL_ALLOW_WITH_REDACTION`
- `FIREWALL_REDACTION_ENABLED`
- `FIREWALL_REDACTION_MASK_PII`
- `FIREWALL_REDACTION_MIN_ENTROPY`
- `FIREWALL_REDACTION_MIN_LENGTH`
- `FIREWALL_REDACTION_MAX_ITEMS`

### Gateway hardening
- `GATEWAY_AUTH_ENABLED=true|false`
- `GATEWAY_AUTH_HEADER=x-api-key`
- `GATEWAY_API_KEYS=key1,key2`
- `GATEWAY_RATE_LIMIT_ENABLED=true|false`
- `GATEWAY_RATE_LIMIT_REQUESTS=120`
- `GATEWAY_RATE_LIMIT_WINDOW_SECONDS=60`

## Docker (prod-like local path)

Build:

```powershell
docker build -t agent-security-gateway:local .
```

Run (auth + rate limit enabled):

```powershell
docker run --rm -p 8000:8000 \
  -e GATEWAY_AUTH_ENABLED=true \
  -e GATEWAY_API_KEYS=dev-secret-key \
  -e GATEWAY_RATE_LIMIT_ENABLED=true \
  -e GATEWAY_RATE_LIMIT_REQUESTS=60 \
  -e GATEWAY_RATE_LIMIT_WINDOW_SECONDS=60 \
  -e FIREWALL_SESSION_DB=/tmp/gateway.sqlite3 \
  agent-security-gateway:local
```

## Local Run / Test

```powershell
pip install -e .
uvicorn gateway.app:app --host 127.0.0.1 --port 8000
python -m unittest discover -s tests -p "test_*.py"
```

## Operational Assumptions and Limitations

- API-key auth is shared-secret based; key distribution/rotation is out of scope.
- In-memory rate limiter is per-process; multi-instance deployments need shared limiter/storage.
- `/health` is intentionally unauthenticated for liveness probes; expose cautiously.
- Rule-based detection/redaction can miss novel encodings and context-fragmented leakage.
- If callers bypass adapters/service and invoke tools directly, enforcement is bypassed.

## Profile Examples

Normal local run:
- `FIREWALL_CONFIG=configs/dev_profile.json`
- `GATEWAY_AUTH_ENABLED=false`

Production profile (recommended baseline):
- `FIREWALL_CONFIG=configs/production_profile.json`
- `GATEWAY_AUTH_ENABLED=true`
- `GATEWAY_API_KEYS=<key>`
- `GATEWAY_RATE_LIMIT_ENABLED=true`

Strict profile (higher sensitivity, higher false-positive risk):
- `FIREWALL_CONFIG=configs/strict_profile.json`
- `GATEWAY_AUTH_ENABLED=true`
- `GATEWAY_API_KEYS=<key>`
- `GATEWAY_RATE_LIMIT_ENABLED=true`
