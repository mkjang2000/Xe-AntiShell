# Managed v1 and Readable Monitoring Panel

## Delivery Scope

Implement and locally validate central enrollment, authenticated durable event
delivery, heartbeat/resources, signed detection policies, and one-time removal
authorization/recovery. Improve the existing monitoring panel with readable
typography, WCAG AA contrast, keyboard operation, service grouping and bounded
server-side history pagination. The user selected this server for initial
central validation; use a separate loopback HTTPS central service.

## Central Validation Deployment

Use a separate Go central binary and SQLite database for the initial single-node
deployment, reusing the validated pure-Go driver. This is a deliberate v1 change
from the earlier PostgreSQL deployment target; keep PostgreSQL migration as a
later central-storage task. The agent never accesses the central database.
Central operator API binds loopback; the agent interface uses TLS and mTLS.
Generate a dedicated CA/server certificate and per-agent CSR/client identity.
Enrollment alone uses an expiring one-use bootstrap credential over verified TLS.
No production auto-response or actual agent deletion is exercised by tests.

## Shared Contracts

`internal/managed` owns signed policy/grant and transport types:

- Record: sequence, kind, id, payload (bounded JSON).
- Batch: enrollment_id, spool_id, records.
- Ack: spool_id, acknowledged (highest committed contiguous delivery sequence).
- Enrollment request: agent_id, csr_pem; response includes enrollment_id,
  certificate_pem, ca_pem, policy_key_id, policy_public_key.
- Heartbeat: status, policy status, resource JSON, enrollment identity.
- Signed policy schema version `1`: existing supported detection settings,
  bounded response requirements/mode/thresholds, uninstall mode, monitoring.
- Signed removal grant: agent/enrollment/challenge/grant/action/expiry binding.

The central service authenticates identity using the verified certificate.
Agent-local enrollment state/outbox persists independently of telemetry-retention
tables. Separate delivery sequence numbers are allocated on durable insertion.
TLS verification cannot be bypassed by accepting the CA returned by enrollment;
the installer/operator supplies an already trusted CA file.

## Agent Integration

Extract an atomic event/process/finding persistence unit and append enabled
delivery records in that transaction. Preserve prior stable event IDs, duplicate
handling and evidence validation. A managed sender worker performs bounded
retries and independent heartbeat/policy polling. It does not block the source
event path on the network. Offline operation retains local detection.

Only verified policies replace approved detection fields. Persist revision and
last-known-good content. Enforcement requires host-local opt-in, verified pidfd
support, live capability gates and strict identity checks. The experimental
actuator sends post-exec SIGTERM and refuses source/procfs timestamp disagreement;
it cannot prevent exec or guarantee exit. Record would-block decisions separately
from evidence confidence. Removal verification consumes
one-use grants/recovery verifiers durably and records intent before a dedicated
removal wrapper may act. Recovery codes are outside-host administrator material,
not a shared TOTP seed on the monitored host.

Resource monitoring uses bounded procfs/sysfs/statfs reads and elapsed counter
deltas for CPU, device I/O and network interfaces. Process identity includes
start time; argv/environments remain excluded. Expose sampling error/freshness.

## Panel Contracts

- GET /api/services -> array of {name, finding_count, event_count}.
- GET /api/history?kind=findings|events&service=&q=&severity=&cursor=&limit=10
  -> {items:[],next_cursor:"",has_more:boolean,total:number}.
- Findings include additive origin_service, populated directly for new rules and
  resolved from stored process context for older history where available.
- Filters and cursor scope validated server-side, maximum page 100; UI page 10.
- Overview remains bounded and does not pretend its recent sample is all history.
- Service panels use native details; tab/filter/page state survives refresh.

## Validation

Unit/race/vet/build and migration/regression checks; enrollment replay and wrong
agent rejection; committed ACK/dedup/offline replay; signed policy tampering and
rollback rejection; removal/recovery replay; metrics reset/bounds tests.
Run actual browser checks with the available local Chrome/Playwright, contrast
measurements and axe/Lighthouse where available. Measure before/after rather
than inventing scores. Check keyboard focus, 200% zoom, 375px layout, service
folding, and history navigation. Keep credentials outside browser artifacts and
reports. Finish with RPM packaging and host verification proportional to risk.
