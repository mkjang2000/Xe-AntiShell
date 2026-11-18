# Purpose and completion criteria

Reduce the cost of the existing observation pipeline on small VPS hosts while
preserving collection scope, detection results, evidence, input validation,
privacy and signed-policy compatibility. Optimize the measured work first.
This document is the implementation plan; it does not record an optimization
as implemented or change the current deployment.

The first reference environment is one vCPU and 1 GiB RAM. Reproduce roughly
400 raw frames/second, including exec/exit, complex ancestry, unchanged and
changed credentials, partial/unknown facts and small file/network traffic.
The local CPU analysis is under devdocs/analysis and is deliberately excluded
from public release artifacts.

## Performance objectives

- First-stage target: at least 50% less end-to-end Agent CPU time per fixed
  input workload. A microbenchmark improvement alone is insufficient.
- Provisional final target: combined sentineld, tetra and Tetragon CPU at or
  below 30% of one vCPU under the defined 400-frame/second steady workload.
  This is a measurement target, not an achieved result or promised reduction.
- Record aggregate RSS, cgroup memory, kernel/BPF memory where measurable,
  GC, allocation rate, local detection/persistence latency and central latency.
  Establish a stable memory bound after ancestry/process caches are populated.
  The OS and application must retain usable memory/CPU within the 1 GiB host.
- No unintended event loss, changed finding/risk/namespace conclusions,
  continuously growing outbox or OOM at the sustained reference workload.
- A short burst test must distinguish recoverable backlog from unsupported
  overload. Report actual accepted/processed/retained/ACK counts and any loss;
  reduced input acceptance is not evidence of improved efficiency.

# Current structure and measured evidence

Credential conversion and validation live in internal/collector and
protocol/model/credentials.go. Fresh source input is normalized, cloned and
validated at the queue boundary, then processed with ancestry before retention,
detection, atomic SQLite evidence/outbox persistence and managed delivery.

The investigation found repeated CredentialSnapshot validation, per-token
regular expressions/maps, temporary credential objects, parent conversion,
multiple event JSON serializations and ancestor projection writes. The live
profile attributed substantial cost to validation, allocation/GC and JSON.
A large outbox was not present during that sample. Normal root executions are
retained even when root_exec_alerts is suspicious.

# Staged design

## 1. Establish differential correctness and repeatable baseline

Build baseline and candidate from fixed source/module versions. Use controlled,
code-free fixtures; do not replay live argv/environment or copy enrollment keys.
Measure 100/400-frame sustained loads and a bounded 800-frame burst, with the
same event sizes, ancestry distribution, expected exclusions and retained data.
Treat the exact skipped-frame mix as a parameter; existing aggregate counters
do not prove that every skip is an unchanged credential event.

Run Agent pipeline tests in a development-host container/cgroup with one CPU,
1 GiB memory and controlled GOMAXPROCS/affinity for both versions. Run producer
and fake central outside the measured Agent budget. This is not a complete
kernel/BPF or full-stack certification.

Use a separate Rocky QA VM with one exposed vCPU/1 GiB for Tetragon + tetra +
Agent end-to-end measurements. Include whole-VM CPU deltas because BPF hook work
can be charged to observed workload processes. Do not generate the heavy test
workload on the production VPS. Repeat trials and run a longer populated-cache
soak; compare CPU time, throughput, latency, memory and output together.

## 2. Low-risk credential and conversion optimization

- Replace CAP token regexp checks with an exactly equivalent ASCII check:
  CAP_ followed by 1..63 characters from A-Z, 0-9 and underscore. Retain valid
  unknown future CAP_* names in the public protocol model.
- Exploit already sorted capability sets for adjacent duplicate checks. Preserve
  acceptance of unsorted unique public inputs with a lazy fallback; never sort
  a caller-owned public slice in place. A fixed known-capability bitset is a
  later option, not required for the first patch.
- Share a private validation/completeness traversal inside the protocol model.
  Public Validate/Complete/Equal still examine current values on every call.
- Reuse local checked results while processing one exclusively owned decoded
  pair, rather than repeatedly validating that same pair for outcome,
  completeness and equality. Unchanged exclusion remains after valid proof.
- Reuse immutable canonical capability strings and avoid redundant conversion
  of the same parent snapshot. Remove copying only where exclusive ownership
  is proven; preserve deep ownership at external/queue boundaries.

Do not attach a validated boolean/cache to mutable public structs or pointer
identity. Do not carry a local validation result across queue/API boundaries.

## 3. JSON, ancestry and storage work

Re-profile after stage2. Separate byte limits, privacy normalization and queue
ownership from their current repeated serialization costs. Keep equivalent
limits and privacy behavior and audit all nested pointer/slice ownership before
combining stages. Preserve source-provided ancestry before deciding web origin.

Convert each parent/ancestor snapshot once per frame. Consider a bounded cache
of immutable normalized context or skipping identical process projections only
with boot/exec/task identity, lifecycle and clock equivalence tests. Canonical
Event/Bundle evidence, atomic finding/outbox transactions and ACK order remain.
Any reusable encoded payload must be immutable and size/encoding-checked.

Do not mix a broad storage rewrite into the first credential patch. Measure
retention cost and database growth even when CPU improves.

## 4. Conditional transport change

If the complete resource budget is still missed, prototype a direct local Unix
gRPC adapter to remove tetra protobuf-to-JSON and Agent JSON-to-typed conversion.
Keep the current adapter for compatibility until equivalence is established.
Review dependencies, SDK compatibility, source health/reconnection, local trust,
input limits, privacy and unknown/oneof fields explicitly.

A protobuf getter returning0 does not establish field presence. Preserve the
separation of missing UID versus UID0 and missing return versus successful0.
Do not claim a fake-server test proves actual Tetragon/BPF behavior.
Kernel-side unchanged suppression is separate research requiring successful,
complete same-hook reads; it is not part of the initial production patch.

# Safety and compatibility gates

- Differential tests for current/candidate event IDs, facts, findings, scores,
  detection-only decisions, signed bytes and privacy output.
- Invalid token bytes/lengths, duplicate and unsorted sets, unknown future names,
  nil versus empty sets, missing IDs versus0, failed/missing return, unknown
  namespace, task mismatch, rapid credential round trips and event retries.
- Clone/mutation tests and race checks: a later mutation must not reuse stale
  validation or change queued/historical evidence.
- No automatic service trust exceptions, sampling or evidence aggregation in
  the initial patch. RustDesk's workload does not grant it detection immunity.
- CPU throttling and memory limits are protection/measurement controls; report
  their effects on queue/latency/loss as part of resource acceptance.

# Delivery

Ship small independently verifiable patches. Publish a protocol patch only if
shared implementation changes, retaining the wire/signature contract. Run
existing unit/race/privacy/compatibility tests, native RPM installation and
controlled replay. Keep live response in observe mode.

After the constrained QA gates pass, sign the packages and update the development
host first. Compare steady workload and actual evidence, then update the VPS.
Confirm collection, policy/enrollment continuity, detection-to-central delivery,
CPU/RAM/GC, queue recovery and a longer observation window. Preserve rollback
packages and queued data. A later transport change receives its own design and
rollout gate rather than being hidden inside the first patch.
