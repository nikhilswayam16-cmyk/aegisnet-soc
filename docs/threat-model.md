# Threat model and safe-use boundaries

## Assets to protect

- Integrity and availability of normalized telemetry.
- Integrity of alert status, evidence and analyst audit history.
- Confidentiality of event metadata and local IOC intelligence.
- Availability of the ingestion API under malformed or excessive input.

## Trust boundaries

1. **Telemetry producers → ingestion API:** all incoming fields are untrusted. Pydantic schemas enforce field types, lengths, IP address syntax, port range and batch size.
2. **API → database:** SQLAlchemy parameterization is used; event IDs are unique; timestamps and evidence are stored as data, not executable instructions.
3. **Analyst browser → write API:** optional API-key verification protects write routes. A production deployment should use SSO/RBAC, TLS and a secret manager rather than a shared static key.
4. **IOC source → IOC store:** this demo has no external feed integration. Indicators are local synthetic records.

## Abuse cases and current mitigations

| Abuse case | Current mitigation | Remaining gap |
|---|---|---|
| Malformed event payload | Schema validation, strict field bounds and IP parsing | Add per-source schemas and quarantine queue |
| Replayed event | Unique event ID / canonical idempotency hash | Define upstream ID trust and retention policy |
| Oversized event batch | Maximum 500 records per request | Add request-body byte limit and rate limiting at proxy |
| Analyst workflow tampering | Audit records are append-only through application routes | Database administrators can still modify SQLite directly |
| Unauthorized writes | Optional constant-time API-key comparison | No user identity, RBAC, SSO or key rotation |
| Alert flood | Correlation fingerprints and bounded evidence | Add quotas, back-pressure, suppression windows and metrics |
| Malicious demo data | Synthetic RFC 5737 addresses and `.invalid` domains | Validate all real integrations in an isolated lab |

## Safe-use statement

AegisNet is for local education, portfolio demonstration and controlled defensive testing. It does not execute shell commands, scan targets, quarantine endpoints or block traffic. Detection findings are signals for human review, not conclusive proof of compromise. Do not ingest sensitive production logs into the demo deployment.
