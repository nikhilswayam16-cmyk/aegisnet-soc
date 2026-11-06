# Interview brief: AegisNet SOC

Use this as a preparation sheet. Be precise about what is implemented and what remains a roadmap item.

## 60–90 second project pitch

> I built AegisNet, an explainable Security Operations Centre prototype. It ingests heterogeneous authentication, endpoint, DNS and network events through a versioned FastAPI contract. The ingestion path validates the schema, creates a stable idempotency key, persists the normalized event and evaluates bounded detection rules. The rule engine correlates repeated signals into alerts rather than creating one alert per event. Each alert carries a risk score, MITRE ATT&CK reference, evidence timeline and audit history. I added an analyst dashboard for triage and status transitions, plus Docker, automated tests and CI. I focused on maintainability and operational behaviour: duplicate handling, bounded queries, explicit workflow transitions and traceable detections.

## Three design decisions worth explaining

### 1. Why idempotent ingestion?

Telemetry producers retry when networks or consumers fail. If the same event is inserted twice, the system can inflate counts and duplicate alerts. A stable upstream `event_id` is preferred; the fallback is a SHA-256 hash of a canonicalized event payload. A production version would also define the event-ID namespace per producer and a retention policy for deduplication keys.

### 2. Why correlate alerts?

A brute-force sequence may produce hundreds of failed-login events. Analysts need one case with a count and evidence list, not hundreds of disconnected notifications. A stable fingerprint groups repeated matches. The current implementation uses source IP for the brute-force fingerprint and bounded evidence records to show why the rule fired.

### 3. Why deterministic rules before ML?

A first security product needs reliable, testable detections and a clear explanation for each alert. Rules provide an auditable baseline and regression suite. Statistical or ML models can be added once representative labeled data, feedback loops and false-positive measurements exist. The DNS entropy detector is explicitly described as a heuristic, not proof of compromise.

## Likely technical questions

**How would you scale ingestion?**

Put a durable broker (Kafka or NATS) between the API and consumers. Partition by tenant/asset or event source, apply back-pressure, batch database writes and scale stateless workers horizontally. Keep event IDs and consumer offsets so retries remain safe. Measure throughput, processing latency, dropped events and queue lag.

**How would you support Zeek, syslog or endpoint agents?**

Add source-specific adapters that parse each producer's schema into the normalized event contract. Preserve source metadata and the original event, version the adapters, reject malformed messages into a quarantine/dead-letter path, and maintain fixtures for parser regression tests.

**How would you reduce false positives?**

Add asset/user context, allow-lists with expiry, maintenance windows, source reputation confidence, suppression windows and analyst feedback. Evaluate rules on labeled replay datasets and track precision, recall, false-positive rate and time-to-detect. Do not silently tune thresholds without regression tests.

**What is missing for production?**

RBAC/SSO, tenant isolation, TLS, managed secrets, migrations, retention and privacy controls, hardened authorization, a broker-backed pipeline, observability, load testing, HA storage, and a formal rule lifecycle. These are listed explicitly in the threat model and roadmap.

**Why is the dashboard not doing automated containment?**

A false positive could disrupt a critical endpoint or network. This prototype keeps actions human-approved and records the analyst's decision. An automated response layer would need policy controls, authorization, dry-run mode, rollback, approval gates and immutable audit evidence.

## Demo sequence

1. Start the server and load the dashboard.
2. Click **Run demo simulation**. Explain that all sample addresses are documentation ranges and the domain ends in `.invalid`.
3. Open `AUTH-001`; show the five failed authentication events and the five-minute threshold.
4. Open `NET-001`; show nine distinct ports within the bounded time window.
5. Open a `THREAT-001` alert; explain the local IOC match and confidence field.
6. Move an alert from Open to Investigating, add a note, then show its audit trail.
7. Open `/api/docs`; show the ingestion schema and the liveness endpoint.

## Honest claims to make

- The project implements six deterministic detections and an offline IOC match.
- The dashboard, ingestion API and analyst workflow run locally.
- Unit tests pass for detection thresholds, input validation and idempotency.
- The current storage backend is SQLite; PostgreSQL, distributed ingestion and RBAC are roadmap items.

Do **not** claim production readiness, real-world detection accuracy, full SIEM/EDR parity, AI-based autonomous response, or affiliation with C-DOT/TRINETRA.
