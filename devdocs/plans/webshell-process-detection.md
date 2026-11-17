# Webshell Process Detection Expansion

## Purpose and Completion Criteria

Improve detection beyond a web-descendant shell without enabling automatic
response. Preserve existing behavior for unchanged local/signed policies and
keep process evidence distinct from proof of a malicious webshell. Provide
positive and legitimate-operation scenarios through the actual persistence
pipeline, with bounded data and readable Korean reasons.

## Current Structure

`internal/detection` evaluates process executions after privacy normalization and
lineage enrichment. Tetragon provides a full process context stream but durable
filters commonly retain shells only. Audit executable filters act before the
common pipeline. Policies replace immutable detector snapshots. Findings are
stored as JSON with explicit evidence links, so additive finding metadata needs
no schema migration. Tetragon flattened arguments are deliberately not retained
or reconstructed as exact argv.

## Design and Scope

- Add optional `detection.extended_process_rules`, false when absent, to local
  configuration and signed policies. Use `omitempty` in signed JSON so old
  signatures still verify. Extended rules require empty executable filters;
  web-origin-only retention can still bound evidence. Reject incompatible
  policies rather than claim coverage for filtered programs.
- Reuse existing web-service/ancestor attribution. Evaluate extra process
  categories: download tools, reconnaissance tools, connection utilities,
  supported inline interpreter invocations, and execution from temporary or
  memory-backed locations. Names are exact; no broad Python/Node suspicion.
- Emit at most one deterministic finding per execution, with fixed IDs and
  bounded additive risk factors. Distinguish root identity, temporary working
  directory and behavioral evidence. Do not infer file writes, network
  connections, successful downloads or a confirmed compromise from exec alone.
- Preserve legacy shell rule IDs and exceptions when the option is false.
  Legacy shell exceptions must not suppress distinct non-shell observations.
  New extended results are explicitly detection-only even under an existing
  enforce policy. Response code must honor this marker independently.
- Keep risk contributions and evidence confidence separate. Never copy command
  strings, URLs, script content or secrets into reasons. Inline-code checks use
  exact argv only; Tetragon cannot supply that signal in this adapter.
- Show Korean rule titles, observed reasons, additive score and detection-only
  state; extend Korean history search consistently.

File modification/network/credential collectors, cross-event attack-chain
correlation, command-content scanning and production blocking remain separate
work. Do not silently expand live collector scope or replace a signed policy.

## Modules and Compatibility

Use an explicit detector Options constructor while retaining existing
constructors. Keep new rule/classifier logic separate from origin attribution.
Add model metadata without changing event/finding schema versions. Introduce a
shareable full-web-origin collection example rather than overwriting local host
configuration. Test default/old-policy compatibility and policy filter limits.

## Validation

Exercise direct and indirect web origins, unrelated SSH/deploy operations,
normal worker interpreters, exact inline-code flags, downloaded-tool execution,
temporary-path boundaries, missing argv/ancestry, reused process identity,
exception scope, deterministic replay and duplicate evidence. Assert actual
findings and metadata survive storage and central outbox serialization. Verify
new findings cannot become termination targets under enforce settings.
Run focused tests, then `make verify`, source hygiene and an RPM build. No live
service restart, collector installation, policy replacement or blocking is
required to validate this code change.

## Validation Results

- `make verify` passed: source/format/shell/JavaScript checks, installer/build
  mocks, Go vet, complete race tests, static binaries and the isolated executable
  replay. The replay needs permission to create its private Unix socket; a
  sandbox-denied launch was diagnosed and rerun with that permission, without
  skipping or weakening the check.
- The binary replay and persistence/managed-outbox matrix covered 16 declared
  scenarios: six observations and ten legitimate/uncertain controls. Rule IDs,
  score contributions, evidence links, detection-only state and source-quality
  metadata matched expectations. Repeated observations stay idempotent.
- Audit count/index/fragment validation has positive and malformed-input
  regressions, including assembler-to-detector checks for sparse argv. Complete
  multi-record groups support argc appearing only in the initial record.
- Legacy policy signatures and defaults remain compatible. New policy scope
  failures preserve the approved detector. Both decision and actuator layers
  refuse extended findings as termination targets; summaries/UI report their
  effective detection-only behavior.
- Built and digest-checked `0.1.0-15.el9.x86_64` with no new dependencies.
  Source hygiene checked 223 source candidates with no findings.
- Live services, host collector scope and signed policies were not changed.
  This is synthetic behavioral/replay validation, not measured real-world
  false-positive or attack-detection performance. Live Tetragon response,
  file/network evidence and production rollout remain outside this change.
