# Purpose and completion criteria

Reduce the cost of the existing observation pipeline on small VPS hosts while
preserving collection scope, detection results, evidence, input validation,
privacy and signed-policy compatibility. Optimize the measured work first.
This document records the staged plan and the measured first delivery below.
Later transport work and the full resource objectives remain separate gates.

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

The first constrained 60-second full-pipeline comparison preserved the exact
source, event and finding hashes but reduced Agent CPU by about 30%, short of
the first-stage 50% objective. This activates the next measured stage; the
first patch is not evidence that the full resource target has been achieved.

The next candidate profile found JSON Decoder.Decode in roughly 37% of CPU
samples and SQLite prepareV2 in roughly 12% (nested cumulative attribution).
Prototype a narrow capability-list decoder before any general transport change.
Only a completely recognized JSON array of unescaped, known pinned ASCII enum
strings may use its fast path. Use immutable canonical strings and one owned
slice; validate whitespace, commas, delimiters and complete consumption. All
escaped/unknown/null/overlong/other inputs fall back to encoding/json decoding
of []string, retaining its type/syntax rejection and future-enum semantics.
Do not skip decoding process/ancestor fields on unchanged credential events.
Compare values, nil/empty and rejection against the standard decoder with
differential/property/fuzz tests and existing full-event goldens. No general
JSON parser replacement or dependency is introduced.

First reuse freshly marshaled event JSON only inside one storage transaction:
keep the public SaveEventResult behavior, return encoded bytes from a private
helper, and use those bytes as the Event field of the managed bundle. Compare
the complete bundle bytes against the existing protocol serializer, including
nil/empty findings, Unicode/HTML escaping and optional observation fields.
Do not skip queue privacy/size validation or cache mutable public evidence.

The RawMessage wrapper prototype passed byte-equality tests but regressed its
serialization benchmark because encoding/json rescans/compacts the event bytes.
Reject that wrapper. Instead assemble the fixed two-field envelope from event
bytes freshly produced by json.Marshal in this same call and separately
json.Marshal'ed findings (including null versus empty arrays). Only this private
provenance is allowed; imported/external byte strings cannot use the helper.
The existing outbox Record validation still validates the resulting JSON.
Keep complete protocol-serializer byte comparisons as an evolution guard and
retain this implementation only if measurements show an actual improvement.

If a new profile confirms material SQLite compile/exec overhead, batch only
the non-context process projections in PersistObservation into a bounded
multi-row UPSERT. Keep SaveProcess unchanged for public callers and retain
operation-specific lifecycle merging. Preserve order with a single-row fallback
for duplicate process keys, validate every row, check RowsAffected against the
number of rows and roll back the whole observation on cross-boot conflicts.
The maximum is 65 rows/910 parameters. Transaction boundaries, FULL durability,
ACK obligations, schema and retained event bytes must remain unchanged. Require
differential row/finding/outbox and rollback/duplicate/lifecycle tests before
the same-input full-pipeline comparison. SQL text reuse is not a prepared SQLite
statement cache in the pinned driver; database/sql PrepareContext alone still
calls prepareV2 and finalize per execution and is not an effective remedy.

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
  the initial patch. A busy service's workload does not grant it detection immunity.
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

## First delivery: RPM28 / protocol v0.3.1

- Fixed release source: d46a468e14ab7bb4790db653300cfd7dda579363.
- Delivered fresh-value credential validation, canonical pinned Capability JSON
  decoding with standard fallback, and same-call event encoding reuse. Queue
  privacy/size checks, retained evidence and atomic outbox obligations remain.
- Controlled same-input 60 s comparison at 400 raw/s in one pinned CPU/1 GiB:
  Agent CPU 66.90% → 44.18% of one core, 40.27 → 26.60 CPU seconds (33.95% less).
  Exact source/event-core/finding hashes and stored/ACK counts matched.
- A 20 min candidate endurance run accepted 480,000 raw inputs, 196,800 normalized
  events and 100,800 stored/ACK records with 4,800 findings. Final delivery pending,
  lost, parse, processing drop and OOM counters were zero in this synthetic run.
  Warmup excluded.
- Endurance Agent CPU averaged 42.13% of one core. After inferred 50K process-cache
  fill, sampled RSS stayed approximately 287–331 MiB. File-cache reclaim pressure
  occurred at the 1 GiB limit; this is not spare-memory certification for apps.
- Fake Central/generator/harness shared the quota; actual Tetragon/BPF were
  absent. The synthetic mix was 20% root exec / 20% exit / 59% unchanged credentials /
  1% restored credentials with 41 caps / 4 ancestors. Other IO/partial cases passed
  semantic tests but are not certified as sustained-load performance by this run.
- The 50% Agent reduction and combined 30%-of-one-core stack targets remain
  unmet/unproven. Normal escaped/unknown Capability inputs retain compatible
  fallback semantics but have higher decoder cost than the pinned fast path.
- Native Rocky 10 units, 68 Python tests, actual RPM installation/integrity,
  replay/clock/credential/privacy/enrollment checks, targeted race/fuzz and
  public Go 1.22/stable CI passed. Compiler runtime sections were identical
  between the benchmark executable and packaged daemon; matching RPM
  postprocessing reproduced the entire packaged binary byte-for-byte.
- Signed RPMs were delivered through scoped Central updates to the development
  host and one VPS. Both completed live collection checks and retained their
  enrollment, signed policies and observe response mode.

## Remaining diagnostics and transport work

The existing aggregate Dropped counter does not distinguish queue timeout from
storage failure, and transient storage errors clear after a successful save.
Per-reason cumulative counts, last occurrence and queue highwater are needed to
explain an earlier transient failure; healthy status alone cannot establish its
cause or prove historical zero loss.

Direct typed Unix gRPC is the next structural candidate for removing the
tetra/JSON round trip. The pinned official Tetragon v1.8.0
[API module](https://raw.githubusercontent.com/cilium/tetragon/v1.8.0/api/go.mod)
requires Go 1.27 while the Agent supports Go 1.22. SDK migration or compatible
client regeneration needs its own design, licensing and OS/wire validation.
Wrapper/oneof presence, nil versus empty caps, omitted namespace bool values,
strict hook proofs, raw/privacy markers, root socket/peer trust and reconnect
gaps must be preserved. This transport is not part of RPM28.
