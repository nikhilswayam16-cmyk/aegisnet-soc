# Roadmap

## Near-term engineering

- Add Alembic migrations and PostgreSQL integration tests.
- Add structured JSON logs, request IDs, Prometheus metrics and `/readyz` dependency checks.
- Add a message-broker adapter (Kafka or NATS) with consumer offsets and dead-letter handling.
- Add per-source parsers for Linux `journald`/auth logs, Zeek JSON, DNS resolver logs and endpoint JSON.
- Add rule configuration files, unit tests per rule, suppression windows and replay-based regression tests.

## Detection quality

- Add host and user baselines with explainable anomaly features.
- Calibrate risk using asset criticality, IOC confidence, alert prevalence and evidence quality.
- Measure precision/recall on labeled, reproducible datasets; publish false-positive and false-negative analysis.
- Add rule versioning and a regression corpus so sustenance changes do not silently alter detection behaviour.

## Product hardening

- Add RBAC, SSO, tenant boundaries, TLS, key rotation and a secrets manager.
- Add event retention controls, encryption at rest and evidence integrity verification.
- Add background workers, bounded queues, back-pressure and load tests.
- Add container scanning, dependency auditing, SBOM generation and release signing.
