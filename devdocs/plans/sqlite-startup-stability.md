# Purpose

Reduce startup database contention on small hosts, retry transient evidence-store
locks without replaying detection/response side effects, and recover only the
error whose operation has actually succeeded. Preserve detection-only settings,
enrollment, policy, data schema and update protocol.

# Evidence and scope

RPM24 already uses WAL, FULL synchronous writes, immediate transactions and a
five-second busy timeout on a four-connection pool. The VPS lock owner is not
known. Central observed continued event processing and a recovered policy while
agent Mode/LastError remained stuck after a prior observation failure.

Startup launches collector processing, delivery, policy polling, metrics and
retention close together. Code changes are limited to storage serialization and
bounded observation transaction retry, independent runtime error state, startup
scheduling, regression tests and RPM25 packaging. Credential detection is deferred.

# Design

- Serialize SQLite access through the agent's owned connection to eliminate
  competing writers inside the daemon; audit nested query lifetimes first.
  Preserve WAL, FULL and immediate transactions. API reads may queue behind
  writes; cancellation and regression tests must cover this tradeoff.
- Retry only failed BEGIN IMMEDIATE writer reservations on typed SQLITE_BUSY/LOCKED,
  before mutation, with two attempts and cancellable 25ms backoff. Keep the
  existing five-second native busy timeout (about ten seconds maximum native
  wait for an external writer, plus context-bound pool acquisition). Do not
  replay transaction bodies or COMMIT failures. Do not rerun event
  normalization, sequence generation, lineage mutation or process response.
  Never retry immutable conflicts or arbitrary filesystem/database failures.
- Keep event persistence and post-commit response errors separate from collector,
  bootstrap and retention state. Only a successful matching operation clears
  its own error. Final persistence failures increment dropped; response errors
  after evidence commit do not count as evidence loss.
- Restore the durable approved policy synchronously before collection. Stagger
  background network/metrics work and delay retention; cancellation must stop
  these waits promptly. Collector event acceptance is not delayed.
- Reuse the signed publisher/central update workflow. First build/test the patch,
  publish immutable new RPMs/manifests, then preview only the approved VPS and
  confirm once if eligible. Do not target the current central host or other agents.

# Validation and failures

Use disposable SQLite databases to hold/release writer locks, exhaust retry,
exercise cancellation and simultaneous policy/delivery/evidence operations.
Verify idempotent event/outbox storage. Regression-test recovery after an actual
failed persistence while preserving collector/maintenance/bootstrap errors;
filtered/invalid input must not falsely clear evidence-store errors.

Run relevant race tests, source checks, package/static and EL10 userspace checks.
Production success requires installed/running RPM25, a new daemon start, fresh
execution receipts and central terminal report/ACK. Observe startup and sustained
health on the VPS; report deployment failure or unknown outcomes without blind
reinstallation. No claim of measured CPU causation or completely lossless input.

# Validation results and remaining limits

- Actual disposable external-writer lock release, exhaustion, cancellation,
  non-contention failure, exact observation/outbox cardinality, concurrent
  evidence/policy/ACK/query and single-pool query cancellation tests pass.
- Agent regression tests confirm only durable persistence clears its error;
  invalid/filtered events do not. Collector/bootstrap/retention/response errors
  survive unrelated storage success. Post-commit response failure does not
  increment evidence dropped. Deferred retention cancels before database access.
- Relevant agent/storage/updater race tests and source checks pass. Packaging,
  platform and production deployment results are recorded separately after build.
- A long external writer can still exhaust both native waits and lead to queue
  overflow. Queue draining uses Background context, while daemon shutdown has a
  bounded main timeout; sustained external locks can exceed that shutdown budget.
  This patch does not establish lossless shutdown under external DB interference.
- Failure accounting is prospective; previously failed observations cannot be
  reconstructed. The actual cause of the VPS's original lock is not proven.
