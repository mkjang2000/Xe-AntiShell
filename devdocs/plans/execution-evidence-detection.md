# Purpose

Extend opt-in web-origin process detection to direct interpreter/script
invocations and privacy-preserving inline-option evidence. Keep every new
finding detection-only and leave unchanged policies on their existing profile.
This document describes the detector implementation and its boundaries to
source collection and future runtime instrumentation.

# Current Structure and Gaps

The existing detector accepted only `process.exec`. The extended profile requires
an exact configured web service or an attributed web ancestor, then observes shell
names, a small exact tool list, temporary/memory executable paths and supported
inline interpreter flags. Root identity and temporary CWD are supporting factors
and do not create findings on their own. Each observation event produces at most
one finding, with a deterministic ID and bounded fixed risk factors. A source
policy signal retains its separate `process.exec_observation` identity.

The inline classifier consumes exact argv and rejects Tetragon's flattened
argument string. It does not inspect command bodies. Normal worker interpreter
executions intentionally do not alert. A renamed interpreter outside an already
suspicious executable path cannot be identified from its filename or attacker-
controlled argv[0]. The new summarizer removes known-runtime arguments before
queueing and again during normalization, after extracting bounded metadata.

# Process Detection Scope

1. Preserve existing shell, tool and temporary-executable observations.
2. Identify a script operand only after a supported interpreter's exact option
   boundaries have been established. Observe temporary, memory or descriptor
   script paths; do not alert on every interpreter or ordinary application
   worker script.
3. Accept inline-option evidence from a typed, validated collector contract or
   exact argv. Keep match-policy evidence distinct from exact argv; never
   reconstruct argv by splitting a flattened command string.
4. Accept runtime classification only from known interpreter names or a trusted
   source proof. A claimed argv[0], generic `-c` flag or script extension does not
   establish that identity. The shipped Tetragon policy adapter accepts known
   runtime binary patterns; arbitrary renamed binaries outside risky executable
   paths remain a coverage gap until a source proves their runtime identity.

All observations require a configured web origin. Missing, redacted or truncated
fields cannot establish a new signal. Resolve relative script paths only with
an available absolute CWD, normalize traversal, and classify path components
rather than substrings. Script arguments establish an invocation attempt, not
proof that the file existed or that its code ran successfully.

# Evidence Interface

The `Event.Execution` contract exposes bounded, code-free facts that distinguish:

- Runtime family and how its identity was established.
- Invocation mode: inline or script. Module and stdin boundaries stop the
  classifier without creating an invocation proof or finding.
- A fixed option identifier or script-path classification.
- Provenance: exact argv versus a reviewed source match policy, including the
  provider/policy version required to interpret the claim.

Code bodies, reconstructed commands, URLs and copied argument values do not
belong in finding reasons. `SummarizeExecution` removes all argv for the five
known runtimes, including ordinary workers and invocations with unsupported
options. Raw payloads for those runtimes and ancestor argv are also removed
before queueing. Existing proof remains intact when the helper runs again on an
already scrubbed event. No code hash or code memory read is required.

This new privacy boundary covers Python, Node, PHP, Perl and Ruby. Existing
shell argv and the general sensitive-argument redactor retain their prior
behavior. Preventing retention of legacy `sh -c`/`bash -c` operands remains a
separate privacy follow-up; the new feature does not claim to solve it.

Unchanged events already in an outbox keep their original bytes. Reprocessing a
pre-upgrade source event with the same stable ID can conflict with its stored
representation because the new privacy pass removes argv and adds bounded
facts. Existing records are not rewritten, and immutable-content comparisons
are not weakened to hide this difference. Such historical source replay needs
a separately reviewed migration strategy.

# Rules, Exceptions and Compatibility

- Add a `web-descendant-temporary-script` observation; retain the existing
  inline rule family and use extended rule version `0.3.0`.
- Keep one primary finding per observation event and fixed, bounded additive
  factors. Scores describe policy weights, not the probability of a compromise.
- Root identity and temporary CWD remain supporting evidence only.
- `allowed_pairs` continues to suppress the shell contribution only. It does
  not exempt a matching execution from independent tool, inline, script-path or
  temporary-executable observations. Do not reclassify ordinary shell `-c`
  invocations as a new interpreter signal merely to bypass a shell exception.
- Preserve the extended-profile opt-in, full executable-filter requirement and
  explicit `DetectionOnly` marker. No new rule may reach the response actuator.

# Module Boundaries

Keep `Engine.Evaluate(event, lineage)` as the service-facing interface for exec
observations. Separate interpreter option semantics into an execution-classifier
module as they grow; keep primary-rule selection and risk attribution in the
extended evaluator. The privileged service should not parse language command
lines or implement detector rules.

File and network facts need their own typed source observations and evaluators;
tool execution alone is not a file-write, connection or download observation.

# Future In-Process Code Execution

In-process dynamic code evaluation may occur without a child or new exec. Such
observations must have a distinct event type and runtime-evidence evaluator,
rather than being represented as a synthetic `process.exec`.

An eventual source contract should bind runtime family/version, validated probe
identity, operation, observation time and bounded result metadata to an exact
boot/process execution identity. Runtime symbol support and attachment must be
validated per runtime/version. Generic compile/eval hooks are common in normal
applications and do not by themselves establish exploitation.

The detector can observe a verified dynamic-code operation within a configured
web origin, then correlate actual file/network observations through a separate
bounded process/time context. It must not collect code bodies, hashes of code,
process environments or arbitrary memory. Until source coverage is verified,
missing runtime telemetry remains unsupported or unverified.

# Validation Plan

- Positive: exact inline-option proof; direct temporary/memory/descriptor script
  operands; relative temporary script with known absolute CWD; verified renamed
  runtime evidence once a source contract exists.
- Negative: ordinary worker scripts/modules, executable prefix lookalikes,
  script arguments resembling interpreter flags, ambiguous/flattened argv,
  unavailable fields, traversal outside risky roots and spoofed argv[0].
- Origin/identity: unrelated SSH/maintenance processes, explicit missing parent,
  reused PID, bounded ancestor traversal and unknown source identity.
- Exceptions: permitted shell observation disappears while independent risky
  execution evidence remains visible.
- Safety/privacy: deterministic replay, one finding per event, bounded scoring,
  no code/secret in reasons or persisted observations, and DetectionOnly under
  an enforce policy.

# Focused Validation Results

Detector unit tests and the existing extended-process/audit-origin agent matrix
passed with protocol v0.1.2 and `GOWORK=off`. The same focused packages passed
the race detector. Privacy tests cover missing/truncated/redacted argv, invalid
UTF-8/NUL arguments, unsupported options, repeated normalization and strict
Tetragon policy/runtime/option tuples.

Operation integration regressions also passed with the race detector: a delayed
operation preserves an evicted durable exit and the newer owner of a reused PID;
source credentials/CWD and ancestor snapshots remain source evidence; a retry
with a changed source parent identity still conflicts. Typed exact proofs reject
missing/truncated argument-quality fields while allowing the deliberate whole-
argv privacy removal performed after proof extraction.

Freshly built temporary daemon/CLI binaries passed the isolated replay check:
20 scenarios, nine observations and eleven legitimate/uncertain controls.
The replay asserts exact sanitized invocation metadata, removed runtime argv,
private-marker absence, fixed risk contributions and detection-only results.
New cases cover direct temporary scripts, Node print, Perl capital-E and normal
worker arguments resembling inline flags. The synthetic program paths and code
strings are metadata and are never executed. No live kernel sensor or production
collector was changed by this validation.
