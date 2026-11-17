# Purpose

Strengthen web-origin non-shell execution and interpreter invocation detection,
then add real file-write and TCP-connect observations. Keep every new finding
strictly detection-only. Design in-process code observation separately.

# Current Structure

The agent normalizes audit/Tetragon exec and exit events, enriches bounded process
lineage, evaluates an immutable detector snapshot, and commits an event plus its
findings and managed outbox atomically. The Tetragon JSON adapter intentionally
omits flattened argv. Shared model aliases use the published protocol module.

# Requirements and Design

1. Extend explicit opt-in execution rules with temporary/memory/fd-backed scripts
   and exact inline options. Preserve normal workers and module boundaries. Do not
   identify renamed interpreters from argv[0] or a flag alone.
2. Extract fixed execution metadata before discarding known interpreter argv and
   raw payloads at the queue boundary. Do not retain code, environment, payloads
   or a hash of code. Tetragon argv strings are never split or reparsed.
3. Tetragon v1.8 raw sched_process_exec argument filters emit separate
   process.exec_observation evidence. Policy names identify one runtime/option;
   option positions are 0–2 after argv[0], with at most two preceding approved
   switches, never a script filename. Three selectors consume six Equal-filter
   maps within the v1.8.0 eight-slot outer map; five positions would require 15.
   This policy-specific bound does not restrict the exact-argv/audit classifier.
   Cache size/argument limits, attachment order and disabled cgroup
   rate limiting must be explicit. Kernel/source support is verified at runtime.
4. Add optional typed execution/file/network fields to Event without altering
   existing signed policy bytes, record kinds or legacy JSON when fields are nil.
   Publish the shared protocol update and pin it in released agent builds.
5. File events use vfs_write return values: positive bytes are written, zero means
   no data, negative means failed. Coverage excludes writev/mmap/io_uring initially.
   TCP v4/v6 connect return zero means initiated, not an established connection;
   failures and missing return values remain explicit. Never collect file or
   socket contents. Retain observations only for configured web origins.
6. Observations attach to existing process identity through context snapshots;
   they must not resurrect a known exit or fabricate another process exec.
   New events are normalized, privacy-bounded, stored and delivered like existing
   evidence. File/network collection alone does not assert malicious behavior.
7. Policy installation is an explicit, monitor-only, transactional local helper
   with owned names/files, pinned definitions and rollback. Existing unrelated
   Tetragon policies/configuration remain untouched. No automatic enforcement.
8. Passive support and actual observation are reported separately. Missing
   policies, unsupported kernels and stale/failed collection remain visible.

# Failure Handling and Compatibility

Reject conflicting typed payloads and impossible outcomes. Cap sizes, process
context, paths and metadata. Preserve source lifecycle and local observation
clocks. Unknown policy events are skipped, not assigned trusted proof. Unknown
argv/partial arguments never establish execution evidence. The central accepts
new event types as string values and retains optional payload fields; heartbeat
struct fields remain unchanged. New model consumers can provide richer display.

# Change Scope

Shared model, collector adapters, detection classifiers, focused normalization
and observation modules, runtime capability reporting, local config validation,
Tetragon policy helper/install integration, local/central evidence presentation,
compatibility tests, release artifacts and documentation. In-process execution
remains a design deliverable, not a claimed implemented capability.

# Validation Plan

Protocol backward-JSON/signature fixtures; classifier legitimate/positive/boundary
cases; strict real-shape Tetragon JSON fixtures; malformed/null/unknown policy
cases; event identity/retry/privacy tests; actual SQLite/outbox/central integration;
helper staged install/rollback tests; source checks/vet/race/static/RPM builds.
Then run benign owned-program probes in an isolated instance before considering
an existing-host detection-only rollout. Do not claim kernel behavior from replay.
