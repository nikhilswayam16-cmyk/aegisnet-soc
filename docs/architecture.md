# Architecture and data model

## Design goals

AegisNet is intentionally designed around product engineering and sustainment concerns rather than a one-off detection script:

1. Accept heterogeneous telemetry through a stable versioned contract.
2. Reject invalid and duplicate events before detection.
3. Keep rules deterministic and explainable.
4. Preserve evidence and analyst actions for later review.
5. Keep the local demonstration reproducible and safe.

## Core entities

- **Event:** immutable normalized observation with source, event type, timestamp, endpoint/network context and a normalized request snapshot.
- **IOC:** local IP, domain or SHA-256 indicator with source, type and confidence.
- **Alert:** correlated detection with a stable fingerprint, rule, risk score, status, ATT&CK metadata and bounded evidence records.
- **AuditEntry:** append-only record of alert creation, reopening and analyst workflow actions.

## Correlation model

The alert fingerprint groups repeated observations by detection identity. Examples:

- `auth-bruteforce:<source-ip>`
- `network-port-scan:<source-ip>`
- `ioc-match:<kind>:<indicator>`
- `large-egress:<asset-or-source>`

This prevents one alert per packet/event and makes a repeated signal update an existing record. The evidence list is capped at 100 records per alert in this prototype.

## Detection design

Each rule has a narrow input domain, a bounded look-back interval or single-event threshold, a stable rule ID and a clear analyst explanation. See the detection catalogue in the top-level README. The thresholds are demonstration defaults, not universal security baselines.

## API contract

The API is versioned under `/api/v1`. Batch event ingestion accepts between 1 and 500 records. Validation runs before persistence. Mutating routes can be protected with `AEGIS_API_KEY`; read routes remain available for the local dashboard. The default configuration is suitable only for local evaluation.

## Operational behaviour

- `/healthz` is a lightweight liveness endpoint.
- API routes return JSON errors with appropriate HTTP status codes.
- Response headers include basic browser hardening directives.
- SQLite is suitable for the single-process demonstration. PostgreSQL is the intended next step for concurrent production use.
