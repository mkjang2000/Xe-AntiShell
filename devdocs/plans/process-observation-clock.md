# Purpose

Prevent valid Tetragon execution/exit events from failing persistence because
source lifecycle timestamps and local observation timestamps were mixed.

# Reproduced Failure

The collector initialized first/last observation from the source event clock.
The lineage tracker then assigned exec last-seen from ingestion and exit
last-seen from source exit time. A source exec slightly ahead of ingestion, or a
delayed parent exit older than a previously received child/ancestor snapshot,
produced `LastSeen < FirstSeen`. Storage correctly rejected the transaction. An
invalid in-memory ancestor could affect subsequent child events as well.

# Design

- Preserve source `EventTime`, `StartTime`, `ExitedAt`, source identity and raw
  payload. Use ingestion time for process and ancestor observation timestamps.
- Give exit processing separate source exit and local observation timestamps.
  Merge observed bounds from actual nonzero observations: earliest first-seen
  and latest last-seen, without inventing offsets or changing lifecycle times.
- Keep existing process identity/boot/PID reuse boundaries and known exit context
  intact. Delayed ancestor snapshots must not revive a closed execution or
  overwrite a newer execution sharing its PID. General duplicate exec-after-exit
  projection semantics are outside this clock correction.
- Ignore only local process/ancestor first/last observation fields when comparing
  a repeated stable source event. Copy ancestor slices before canonicalization;
  genuine source payload differences must still conflict.
- Keep SQLite validation and atomic evidence/finding/outbox transactions. Keep
  existing fail-closed health behavior for actual storage failures; do not make
  the panel green by suppressing errors. Applying the fixed agent restarts its
  in-memory graph using the live process snapshot.
- No schema, central protocol, key, policy, response opt-in or collector-service
  change is needed. A normal agent RPM upgrade preserves existing state.

# Validation

Replay future-source exec timestamps and delayed exit-after-ancestor sequences
through the real collector, lineage tracker, SQLite store and managed outbox.
Include a subsequent child, clock rollback, out-of-order/repeated observations,
PID reuse, same-source retry with a new ingestion time, and changed-source
conflicts. Preserve existing strict storage tests. Run full verification and a
native EL10 build/install plus managed enrollment regression before distribution.

# Deployment Boundary

The central server cannot execute an agent package upgrade remotely. Provide a
reviewed RPM and normal upgrade instructions for the target operator, then
confirm a new daemon start, healthy collection and continuing central delivery.
Earlier rejected events were not durably queued; this fix does not promise to
reconstruct records already lost before the upgrade.
