# Purpose and acceptance

Add opt-in global root-execution observation and kernel credential-change
detection, independently of configured web origins, with central policy/UI
support. Deploy detection-only to the two currently enrolled Tetragon hosts
after tests and signed package verification. Preserve approved policies,
enrollments and response opt-in; never automatically terminate from these rules.

# Current structure and evidence

RPM25 contains serialized SQLite and independent recoverable runtime errors.
Existing detection is web-origin exec/inline classification. Tetragon observation
adapters accept only fixed policy/hook tuples; file/network operation context is
not allowed to rewrite historical exec credentials or revive exited processes.
The protocol module is independently versioned and used by both projects.

Pinned Tetragon v1.8.0 has a commit_creds policy and current_task/resolve data
arguments. A candidate policy captures argument0/new credentials and current
task cred/old credentials at entry, merging a return event by TID and kernel
entry timestamp. Actual target-kernel attach and observed event shape must be
verified before claiming applied transitions. Cached process metadata alone is
never proof of the previous credential state.

# Contract

- Add optional `privilege_rules` bool and `root_exec_alerts` enum (omitted/default
  suspicious, or all) to local/signed detection policy. False/omitted retains
  legacy signed bytes. The existing overall detection.enabled gate remains.
- Add optional process TID, user-namespace metadata and exec privilege metadata.
  Add typed `credential` observation on `process.credential_change`: bounded
  before/after snapshots, evidence kind, fixed policy/function, return/outcome.
  Unknown numeric/namespace/capability information remains explicitly unknown.
- New capabilities separate static engine contract support from live credential
  receipt. Old agents cannot receive a true new policy; central preview,
  confirmation and direct admin assignment all enforce compatibility.
- Root execs are retained globally only under the opt-in profile, bypassing web
  retention without disabling existing web detection. Normal root activity is
  still evidence; suspicious mode limits findings to explicit contextual
  signals. All mode permits low-severity findings for every observed root exec.
  Executing as root is not the same fact as a new PID or proven escalation.

# Sensor and detection

- Use a separate fixed monitor-only commit_creds policy, without the upstream
  example's host-excluding selector or one-minute event throttling. Collect
  before/current_task.cred, after/arg0 and return0. Parse strict reviewed tuple
  and bounded metadata; never collect argv, environment or raw event payloads.
- Return0 plus complete paired same-hook evidence supports applied transitions.
  Missing reads/return/TID or ambiguous namespace cannot establish host-root
  elevation. Unchanged credentials are not stored as changes.
- Distinguish nonroot-to-root, root-to-nonroot, effective capability gains and
  container/non-host/unknown user namespace. Do not claim exploit attribution.
  Separate events remain linked to the same exec generation/TID without
  overwriting the execution snapshot. PID reuse and delayed events must not
  borrow newer-owner identity.
- New findings are detection-only. Normal sudo/su and service activity are
  observations, not automatically malicious or globally trusted exceptions.
  Neither root parent nor executable basename alone establishes authorization.

# Activation and trust boundary

A separate agent controller reconciles only the embedded fixed policy through
the configured trusted tetra binary and Unix socket after signed/local opt-in.
It has no arbitrary YAML/command/URL interface. Private state/ownership markers
are under the agent state directory; pre-existing non-owned same-name policy is
not replaced. Disabling removes only the owned policy. Collector startup and
normal collection remain independent of controller failure. Active capability
requires real typed receipt, not just successful policy listing.

# Central and UI

Update policy checkbox/mode, old-agent compatibility gates, capability explanations,
credential event types/details and new finding labels in both monitoring panels.
Preserve legacy policy/template round-trips and old omitted-field signatures.
Do not require already-active credential observation to authorize the opt-in
that attaches the sensor. Role checks and signed-policy workflow are reused.

# Validation and rollout

Test false/omitted policy compatibility, strict malformed/partial credential
evidence, before/after/TID/namespace, rapid changes, duplicates, exits/PID reuse,
global retention and web-rule preservation, normal root activity, would-block/
enforce refusal, controller ownership/rollback/cancel and central preview/admin
compatibility. Test real attach with bounded owned-process UID changes, not an
exploit. Report any unavailable hook/field as limited, not fabricated proof.

Build/sign agent EL9/EL10 and central packages from reviewed commits. Deploy
central support first, then agents one at a time through the existing signed
updater. Enable the profile only after new engine capability is received.
Observe health/DB errors/drop/CPU and real credential receipts per host. A failed
or unknown rollout is not blindly retried. Root/credential rules remain observe
only throughout; no denial policy or automatic process kill is introduced.

# Limits

No independent fork-only sensor, full kernel/rootkit protection, TPM attestation,
complete RCE detector, authorization proof for sudo, or guaranteed lossless stream.
Credential monitoring and extra global exec retention add cost; validate on the
one-vCPU VPS before broadening. Incompatible collectors remain explicitly limited.

# Review corrections and validation boundaries

The shared contract was published as protocol/v0.3.0 after protocol race/vet,
legacy signed-policy fixture tests and the bounded Rocky9 live kernel proof.
The source uses one strict event-argument allowlist across local configuration,
managed-policy acceptance and static engine capability, preventing filtered or
redacted credential proof from being advertised as supported. Privacy-only
argv/environment exclusions remain allowed.

Controller recovery from endpoint/list/not-ready intervals resets the receipt
epoch even if the socket/name is unchanged. Delayed queued events retain the
older of source event and ingress times; processing time cannot activate a new
attachment epoch. A precise missing namespace-scope advisory allows generic
identity/capability findings while all actual missing/redacted/truncated proof
still fails closed. User-namespace inode and host classification are separate.
Task start nanoseconds use decimal strings over JSON to preserve all uint64 bits.

Routine root exec evidence is retained in suspicious mode, so alert suppression
does not bound event-storage volume. Queue, identity graph, input/output sizes
and retention remain bounded by existing mechanisms, but sustained all-host
credential/exec workloads and long-running completeness are not certified.

On the development host the unchanged hostmetrics privacy test was separately
observed failing from asynchronous external IN_OPEN notifications: strace showed
no sampler open of synthetic cmdline/environ, and a Python inotify-only fixture
with no sampler also received IN_OPEN after100ms. Do not weaken this test to
hide the environment issue; rerun unchanged tests in isolated EL10 QA and report
both results. This observation is not a production privacy exception.
