# Agent Security Gateway

**A production-hardened, stateful security gateway for AI agents that inspects prompts, tool calls, session behavior, approvals, and outputs before execution.**

**Secure the agent before it acts.**

Agent Security Gateway is a control layer that sits between an agent runtime and real side effects. It inspects input risk, planned actions, tool execution, session buildup, approval requirements, and returned outputs before sensitive operations are allowed to proceed.

The system is designed for agent environments that can touch shell, filesystem, network, memory, and other high-risk execution surfaces. It combines deterministic policy enforcement with session-aware escalation, approval control, central redaction, and operator visibility.

This repository is a serious internal baseline for securing agent execution paths. It is not a claim of complete agent safety, and it should be deployed as one layer in a broader defense-in-depth stack.

---

## Why this exists

Modern agent systems can move from text to action quickly. That creates a dangerous gap between what the model *intends* and what the system *actually executes*.

This project closes that gap by introducing a dedicated gateway that:

- inspects prompts, outputs, and tool calls before execution
- tracks risk across multi-step sessions
- mediates execution through controlled adapters
- requires approval for high-risk actions
- sanitizes sensitive outputs before they are returned
- exposes audit and operator visibility for review

---

## Architecture

```text
User / Agent Runtime
        |
        v
Agent Security Gateway
  - Detection
  - Policy
  - Session Risk
  - Approval
  - Redaction
  - Audit
  - Auth / Rate Limit / Metrics
        |
        v
Controlled Adapters
  - Shell
  - Filesystem
  - HTTP
  - Memory
        |
        v
Execution Surfaces
```

### Core design rules

- **Single enforcement path:** security decisions are made in the gateway/service layer.
- **Thin adapters:** adapters do not implement their own policy engines.
- **Fail closed:** invalid auth, invalid approvals, replayed permits, and denied decisions do not execute.
- **Central redaction:** sensitive output masking happens in one pipeline, not in scattered tool wrappers.
- **Session-aware evaluation:** repeated lower-risk behavior can escalate to a higher-risk decision over time.

---

## What this repo provides

### `firewall` library
The security core used by both direct code integration and the HTTP gateway.

Includes:
- deterministic detectors
- chain guard
- policy engine
- session risk evaluation
- approval persistence
- audit persistence
- redaction pipeline
- logging utilities
- thin execution adapters
- direct library and CLI entrypoints

### `gateway` service
An HTTP service layered over the firewall library.

Provides:
- inspection endpoints
- approval endpoints
- operator overview and session timeline
- health and readiness probes
- metrics endpoint
- auth and rate limiting middleware

---

## Core capabilities

- Prompt injection detection
- Secret leakage detection
- Unsafe tool-abuse detection
- Action-chain risk analysis
- Session-aware escalation
- Approval-gated execution for risky actions
- Central output redaction
- Operator console and timeline APIs
- Auth, rate limiting, metrics, and health checks
- Docker-ready deployment path

---

## Decision model

The gateway can return the following enforcement decisions:

- **allow** — execute normally
- **allow_with_redaction** — execute, but sanitize output before returning it
- **challenge** — deny execution by default and require further handling
- **require_approval** — execution paused pending approval
- **block** — deny execution

### Important behavior

- `allow_with_redaction` only upgrades from a base `allow`
- a true `block` remains `block`
- approval only satisfies the approval gate for the exact approved action context
- approval does **not** bypass other inspection logic

---

## API surface

### Health / readiness / metrics
- `GET /health`
- `GET /ready`
- `GET /metrics`

### Inspection
- `POST /inspect/input`
- `POST /inspect/tool-call`

### Approval
- `POST /approval/submit`
- `POST /approval/resolve`

### Operator visibility
- `GET /operator`
- `GET /operator/api/overview`
- `GET /operator/api/session/{session_id}/timeline`

---

## How enforcement works

### Pre-execution path
1. Agent proposes input or tool action
2. Gateway normalizes request context
3. Detectors inspect content and intent
4. Session risk is loaded and evaluated
5. Policy returns a decision
6. Execution is allowed, blocked, challenged, or paused for approval

### Post-execution path
1. Tool output is sent through the central redaction pipeline
2. Sanitized output is used for post-inspection
3. Decision metadata and audit records are updated
4. Caller receives either safe raw output or sanitized output

---

## Redaction pipeline

Redaction is centralized in the service layer.

### Supported masking
- secret key/value forms such as `api_key=...` and `token=...`
- JWT-like and AWS-key-like patterns
- high-entropy token masking
- optional PII masking for email, phone, and SSN

### Deterministic token format
```text
[REDACTED:<kind>:<sha256-prefix>]
```

### Example
Raw:
```text
api_key=SECRET123 user=alice@example.com
```

Sanitized:
```text
api_key=[REDACTED:secret:...] user=[REDACTED:pii_email:...]
```

---

## Adapters

All adapters are intentionally restricted and enforcement-only.

### ShellAdapter
- `shell=False`
- executable allowlist required
- timeout and output-size caps

### FileSystemAdapter
- rooted base directory only
- path traversal rejected
- bounded read/write sizes

### HttpAdapter
- only `GET` and `POST`
- host allowlist required
- bounded response size

### MemoryAdapter
- minimal key/value read/write only

### Adapter rules
- pre-inspect → enforce → execute → sanitize → post-inspect
- adapters do not embed policy logic
- blocked and challenged actions do not execute by default

---

## Session-aware risk

The gateway tracks risk across requests within a session.

Stored session state includes:
- session ID
- agent ID
- prior actions
- memory touched
- cumulative risk
- prior decisions
- sensitive markers
- timestamps and request count

This allows the system to detect:
- repeated sensitive actions
- cross-call unsafe chains
- staged escalation patterns
- session-level buildup not visible in a single request

---

## Approval workflow

The gateway supports one-time, expiring, action-bound approval permits.

### Approval lifecycle
1. inspection returns `require_approval`
2. operator submits approval request
3. operator resolves request as approved or denied
4. an approved request issues a short-lived permit token
5. caller retries with the approval token
6. gateway validates token, context match, expiry, and single-use status
7. permit is consumed if valid

### Approval guarantees
- bound to normalized action context
- one-time use
- expires
- replayed permits fail closed
- denied permits fail closed
- approval does not override a true block

---

## Operator console

The operator view provides a minimal visibility plane for:

- recent sessions
- flagged events
- approval state
- decision history
- per-session timeline

The console is intentionally lightweight. It is meant to support review and debugging, not to be a full SIEM replacement.

---

## Quickstart

### Local install
```powershell
python -m pip install -e .
```

### Run the gateway
```powershell
uvicorn gateway.app:app --host 127.0.0.1 --port 8000
```

### Run tests
```powershell
python -m unittest discover -s tests -p "test_*.py"
```

---

## Production-like local run

```powershell
$env:FIREWALL_CONFIG="configs/production_profile.json"
$env:GATEWAY_AUTH_ENABLED="true"
$env:GATEWAY_API_KEYS="dev-secret-key"
$env:GATEWAY_RATE_LIMIT_ENABLED="true"
$env:GATEWAY_RATE_LIMIT_REQUESTS="120"
$env:GATEWAY_RATE_LIMIT_WINDOW_SECONDS="60"
uvicorn gateway.app:app --host 127.0.0.1 --port 8000
```

---

## Docker

### Build
```powershell
docker build -t agent-security-gateway:local .
```

### Run
```powershell
docker run --rm -p 8000:8000 ^
  -e GATEWAY_AUTH_ENABLED=true ^
  -e GATEWAY_API_KEYS=dev-secret-key ^
  -e GATEWAY_RATE_LIMIT_ENABLED=true ^
  -e GATEWAY_RATE_LIMIT_REQUESTS=60 ^
  -e GATEWAY_RATE_LIMIT_WINDOW_SECONDS=60 ^
  -e FIREWALL_SESSION_DB=/tmp/gateway.sqlite3 ^
  agent-security-gateway:local
```

---

## Example API flow

### Inspect a risky tool call
```bash
curl -s http://127.0.0.1:8000/inspect/tool-call \
  -H "content-type: application/json" \
  -H "x-api-key: dev-secret-key" \
  -d '{
    "session_id":"sess-1",
    "agent_id":"agent-a",
    "tool_name":"shell",
    "action":"cat ~/.ssh/id_rsa"
  }'
```

### Submit approval
```bash
curl -s http://127.0.0.1:8000/approval/submit \
  -H "content-type: application/json" \
  -H "x-api-key: dev-secret-key" \
  -d '{
    "session_id":"sess-1",
    "agent_id":"agent-a",
    "tool_name":"shell",
    "action":"cat ~/.ssh/id_rsa"
  }'
```

---

## Configuration

### Firewall / redaction
- `FIREWALL_CONFIG`
- `FIREWALL_SESSION_DB`
- `FIREWALL_ALLOW_WITH_REDACTION`
- `FIREWALL_REDACTION_ENABLED`
- `FIREWALL_REDACTION_MASK_PII`
- `FIREWALL_REDACTION_MIN_ENTROPY`
- `FIREWALL_REDACTION_MIN_LENGTH`
- `FIREWALL_REDACTION_MAX_ITEMS`

### Gateway controls
- `GATEWAY_AUTH_ENABLED=true|false`
- `GATEWAY_AUTH_HEADER=x-api-key`
- `GATEWAY_API_KEYS=key1,key2`
- `GATEWAY_RATE_LIMIT_ENABLED=true|false`
- `GATEWAY_RATE_LIMIT_REQUESTS=120`
- `GATEWAY_RATE_LIMIT_WINDOW_SECONDS=60`

---

## Profiles

### Dev
- `FIREWALL_CONFIG=configs/dev_profile.json`
- auth disabled by default
- easiest local workflow

### Production
- `FIREWALL_CONFIG=configs/production_profile.json`
- auth enabled
- rate limiting enabled
- recommended baseline deployment profile

### Strict
- `FIREWALL_CONFIG=configs/strict_profile.json`
- higher sensitivity
- more aggressive blocking and redaction posture
- greater false-positive risk

---

## Threat model

This gateway is designed to reduce risk from:

- prompt injection
- indirect tool abuse
- secret leakage
- unsafe action chains
- risky multi-step sessions
- sensitive output exposure

It does **not** guarantee:
- complete jailbreak prevention
- semantic-perfect attack understanding
- protection if tools bypass the gateway
- global multi-instance rate-limit enforcement in the current design
- enterprise identity and key-management maturity in the current release

---

## Operational assumptions and limits

- API-key auth is shared-secret based
- in-process rate limiting is per-instance, not cluster-global
- `/health` and `/ready` are intentionally probe-friendly and should be network-restricted
- rule-based detection and masking can miss novel encodings or fragmented leakage
- some benign high-entropy strings may be masked by design
- SQLite is used as a practical local/internal persistence baseline
- this project should be deployed alongside sandboxing, IAM, egress control, and secret managers

---

## Repository structure

The current repository layout includes the root files, config profiles, firewall library, gateway service, benchmark script, and tests shown in your actual tree. fileciteturn3file0

```text
.
├── .dockerignore
├── .gitignore
├── Dockerfile
├── firewall_config.example.json
├── gateway_sessions.sqlite3
├── pyproject.toml
├── README.md
├── configs/
│   ├── dev_profile.json
│   ├── production_profile.json
│   └── strict_profile.json
├── firewall/
│   ├── __init__.py
│   ├── adapters.py
│   ├── api.py
│   ├── approval_store.py
│   ├── audit_store.py
│   ├── chain_guard.py
│   ├── client.py
│   ├── config.py
│   ├── detectors.py
│   ├── engine.py
│   ├── gateway.py
│   ├── logging_utils.py
│   ├── main.py
│   ├── models.py
│   ├── policy.py
│   ├── redaction.py
│   ├── session_risk.py
│   ├── session_store.py
│   └── types.py
├── gateway/
│   ├── __init__.py
│   ├── app.py
│   ├── controls.py
│   ├── routes_approval.py
│   ├── routes_health.py
│   ├── routes_inspect.py
│   ├── routes_operator.py
│   └── service.py
├── scripts/
│   └── benchmark_firewall.py
└── tests/
    ├── corpus/
    │   └── security_cases.json
    ├── test_adapters.py
    ├── test_adversarial_vectors.py
    ├── test_approval_flow.py
    ├── test_cli.py
    ├── test_config.py
    ├── test_corpus.py
    ├── test_engine.py
    ├── test_firewall.py
    ├── test_gateway.py
    ├── test_gateway_http.py
    ├── test_operator_console.py
    ├── test_redaction.py
    ├── test_redaction_gateway.py
    └── test_types_api.py
```

---

## Test status

The current baseline was validated with:

```powershell
python -m unittest discover -s tests -p "test_*.py"
```

Expected outcome for the current validated baseline:
```text
Ran 86 tests ... OK
```

---

## Roadmap

- stronger authentication beyond shared API keys
- shared-state rate limiting for multi-instance deployment
- PostgreSQL-backed persistence
- replay and trace analysis tools
- richer policy packs for different agent classes
- semantic classifier fallback for hard cases
- deeper adversarial corpus expansion

---

## Security notes

This project is best understood as a **security gateway for agent execution**, not as a universal guarantee of safety.

Its value comes from:
- enforcing a single control path
- mediating execution surfaces
- making risk visible
- requiring approval where necessary
- reducing sensitive-output leakage

Use it as part of a layered system, not as the only line of defense.
