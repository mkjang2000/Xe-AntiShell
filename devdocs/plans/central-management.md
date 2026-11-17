# Central Management Before Installation Automation

## Status and Purpose

Agreed development sequence, 2026-11-16:

1. Build authenticated central integration and durable remote history.
2. Add host monitoring and versioned detection-policy distribution.
3. Package the validated standalone/managed workflows in `install.sh`.

Implementation status: managed v1, resource monitoring and `install.sh` are now
implemented and validated on a Rocky Linux 9 host. Central v1 deliberately
uses separate SQLite storage; PostgreSQL and a multi-host central web UI remain
later work. See `managed-v1-and-panel-accessibility.md` and
`../analysis/managed-v1-operations.md` for the implemented contract and operations.
The following structure/design sections describe the original planning baseline.
The updated detection/response, policy-protection, removal, resource-monitoring,
and deferred-integrity requirements are specified in
`security-policy-and-monitoring.md`.

## Current Structure

- `internal/agent` selects a source, evaluates local rules, and persists evidence.
- `internal/storage` owns SQLite events, findings, process context, and sequences.
- `internal/localapi` exposes a host-local Unix-socket API.
- `internal/webpanel` provides authenticated local monitoring.
- Events are assigned source sequences before candidate filtering, so retained
  records intentionally have sequence gaps. These are not transport loss.
- At the planning baseline, evidence writes used separate transactions. Managed
  v1 now commits evidence, findings and delivery obligations together.
- The planning baseline had no central sender, outbox, enrollment, heartbeat,
  or policy service. Managed v1 now implements those separate modules.

## First Central Scope

- Register and revoke individual agents, with persistent host identity.
- Receive normalized candidate events, findings, and their evidence/context.
- Show hosts, services, findings, capability/runtime status, and delivery lag.
- Report collector health/loss, agent version, last server contact, and current
  desired/applied policy version independently.
- Distribute versioned monitoring/detection policies with per-host outcomes.
- Carry signed response authorization, removal policy, and security audit
  events according to the managed policy specification.
- Receive bounded CPU/RAM/disk/disk-I/O/process/interface telemetry, with
  explicit freshness and collection errors.
- Continue local collection/detection using the last valid policy while offline.

## Boundaries and Interfaces

The central service is a separate Go process. Keep the agent's SQLite ownership
and local API intact; add explicit remote-protocol, delivery, and policy modules
instead of putting network behavior inside collectors or entry points.
PostgreSQL remains a future central-storage direction; managed v1 uses a separate
SQLite database. Deployment addresses are selected for each environment.

All agent traffic is initiated outbound over authenticated HTTPS with mTLS.
Enrollment uses a scoped, expiring, single-use bootstrap credential and a
verified server identity. Enroll host keys individually; support revocation,
renewal, and safe retries. Enrollment secrets do not appear in URLs, command
arguments, ordinary logs, or installer output. Operator authentication is
separate from agent identity, with viewer/policy-admin permissions and an audit
trail for enrollment, policy changes, and assignments.
Enrollment also provisions host/enrollment-scoped verification material for
one-time removal grants and independently retained offline recovery codes;
see the emergency removal design in `security-policy-and-monitoring.md`.

## Data Flow and Delivery

```text
local source -> normalization/detection -> evidence + durable delivery outbox
                                         -> authenticated batch sender
                                         -> central transaction and dedup
                                         -> committed acknowledgement
```

Define an atomic persistence boundary for evidence, findings, and their delivery
obligations before adding a sender. A crash between current independent writes
must be recoverable without depending on the external source replaying events.

Use a separate durable delivery cursor, scoped by enrolled agent and spool
generation. Keep original boot/source sequences as evidence. Central dedup is
scoped to authenticated agent identity, record kind, and immutable item ID; a conflicting
duplicate is rejected. ACK only committed data, and advance the durable local
checkpoint only after validating the server acknowledgement. A lost response
or restart resends the same items safely. Persist spool generation so database
replacement cannot silently reuse an old delivery identity.

Outbox byte/age limits, batch/body limits, retry backoff, retention interaction,
disk-full handling, and intentional eviction must be explicit and observable.
Normal evidence retention cannot silently remove pending delivery obligations.
Heartbeat and policy checks have bounded independent work so an evidence
backlog cannot indefinitely hide host status or policy outcomes.

## Host and Policy State

Central receive time determines contact freshness; host clock time is evidence.
Show disconnected, collector-error, degraded, healthy, and unverified integrity
separately. A heartbeat is not proof of host integrity or complete collection.

The agent polls its assignment; policy content follows a strict versioned
schema for supported detection rules, origins, exceptions, and retention limits.
Host-local keys, paths, command specifications, collector installation, and
bootstrap configuration remain locally controlled.

Track desired version, fetched version, active version, failure reason, and
application time. Check authenticity, digest, schema, runtime capabilities, and
resource bounds before activation. Retain a known-good policy and stage an
atomic activation/recovery path. Reject invalid or unsupported changes without
stopping the detector. An administrator-requested rollback is a new audited
revision, not an unauthenticated downgrade.

## Implementation Milestones

1. Shared protocol, agent identity/enrollment, and authenticated server storage.
2. Transactional outbox, batch ingestion, dedup/ACK, offline recovery tests.
3. Heartbeats, delivery health, host/service monitoring and history queries.
4. Signed policy assignment, safe agent activation, outcome/audit history.
5. Dry-run response validation and separately authorized scoped enforcement.
6. Resource monitoring and end-to-end validation, then the installation wrapper.

The installer will support standalone and managed modes. Managed setup takes
the central endpoint, trust configuration, and protected enrollment input,
selects/validates a usable collector, enrolls, obtains the initial assignment,
and reports a completed health/canary result. Reinstall/upgrade preserves
existing identity, local configuration, credentials, and evidence. Do not copy
another host's concrete service/container identifiers to unrelated hosts.
Initial managed setup must also establish an administrator-held recovery route
that works during central failure. Ordinary upgrades preserve it, and normal
remote policy edits cannot silently revoke it.

## Completion Tests

- Two agents cannot submit for or obtain the policy of one another.
- Invalid/revoked credentials and repeated enrollment are handled safely.
- Server failure, lost ACK, agent restart, and retry preserve pending data and
  produce no duplicate history or false transport gaps from source filtering.
- A batch with two candidates separated by 100 filtered source events advances
  the delivery ACK normally; source gaps are not reported as transport loss.
- Crash injection between storage boundaries does not strand findings or
  references to evidence that was never delivered.
- Quota/disk/retention failures appear as explicit backlog/loss conditions.
- Offline hosts continue detection and later deliver backlog with bounded work.
- Invalid/unsupported policy leaves the active policy unchanged; restart during
  activation and intentional rollback recover to an unambiguous revision.
- Server monitoring distinguishes last contact, collector activity, candidate
  activity, delivery lag, and integrity-verification state.
- Canary evidence and policy status are visible centrally before installer work.
- Central unavailability does not prevent authorized emergency removal; consumed
  recovery codes and grants cannot be reused through ordinary supported paths.
