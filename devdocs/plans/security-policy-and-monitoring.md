# Managed Detection, Response, and Host Monitoring

## Agreed Scope

Updated requirements, 2026-11-16:

1. Webshell detection and controlled response.
2. Central-server and agent integration.
3. Authentic, versioned, centrally controlled policy in managed mode.
4. CPU, RAM, disk capacity, disk I/O, process, and network-interface monitoring.

Process-memory integrity checking and TPM/IMA integrity verification are later
work. Installer automation follows the validated central enrollment/policy flow.
Managed v1 now implements signed remote policy, durable central delivery,
removal authorization/recovery and resource monitoring. The current host remains
in observe mode. The opt-in post-exec SIGTERM actuator is experimental and
conservatively refuses uncertain process identity; it is not pre-exec prevention.
See `managed-v1-and-panel-accessibility.md`, the operations document and the
managed-agent security review for implementation details and limits. The design
below retains the agreed requirements and the original baseline for context.

## Existing Behavior

- The local detector identifies configured web-origin shell executions.
- EUID 0 selects critical severity; other matched shells select high severity.
- Finding confidence 0.55/0.75/0.95 represents lineage evidence quality, not
  maliciousness probability or a calibrated response score.
- Ordinary PM2 deployment shells have already matched this rule. A verified
  lineage by itself is insufficient to authorize termination.
- The host receives Tetragon process exec/exit data. File/network/credential
  observation and general resource telemetry are not implemented yet.

## Policy Decision Model

Keep these inputs independently visible and auditable:

- `capability_gate`: the required observation and action features actually work
  on this host. Kernel/BTF presence or a collector binary is not enough.
- `risk_score`: versioned rule evidence describing suspicious behavior. Missing
  evidence is explicit; do not manufacture a low score from absent telemetry.
- `evidence_confidence`: source completeness and reliable process attribution.
- `response_authorization`: valid assigned policy, mode, scope, and exceptions.

Policy acceptance must be feature-granular. Process observation, safe targeted
signalling, and inline execution denial need different runtime checks. eBPF
support alone cannot authorize every response type. An optional capability
summary score may inform operators, but hard prerequisites gate each action.

```text
valid assigned policy + enabled response mode
  + required capabilities operational
  + risk threshold met + minimum evidence confidence met
  + permitted target scope + no matching exception
  + current process identity verified
  -> eligible response action
```

Store score contributions, rule/model version, capability snapshot, policy
revision, matching exception, requested action, and actual outcome. Decide
thresholds using labelled positive/negative tests and operational false
positives rather than interpreting 0.95 as 95% attack likelihood.

## Response Semantics and Rollout

Expose separate modes: observe, would_block, and enforce. `would_block` records
the exact decision and target without changing application state. Active mode
requires an explicitly authorized policy after dry-run validation, preserving
the earlier detection-first operating requirement.

Distinguish post-detection targeted termination from in-kernel denial before a
specific protected operation. A post-exec userspace decision cannot promise
that the process performed no harmful operation before termination. Inline
enforcement needs separately validated hooks/actions on each kernel and cannot
be assumed from receipt of a process_exec JSON event.

Use boot/exec identity, PID, event freshness, exact origin, and an appropriate
kernel process handle when available. A process handle prevents PID-number
reuse confusion but is not proof of an unchanged executable. Expired or
ambiguous targets produce explicit skipped/target_expired outcomes. The first
actuator scope is a specifically identified process; service-wide or host-wide
actions require their own explicit policy and testing.

Required-capability loss restricts response and produces a degradation event.
Continue usable local detection with its actual coverage. Keep service-scoped
exceptions narrow; normal deployment behavior must not implicitly allow every
shell under an entire web service.

## Managed Policy Authenticity and Local Control

Use authenticated transport plus independently verifiable signed policy
content. Bind signatures to schema, policy ID, revision, targets, content,
validity, and signer key. Provision verification keys securely; support key
rotation and reject unauthorized replacements, replay, and stale assignments.

Validate schema, resource bounds, capabilities, policy scope, and content
before atomic activation. Report desired/fetched/active revisions and failures.
Maintain a known-good policy and unambiguous restart/rollback behavior.
Managed local CLI/UI edits cannot silently override centrally governed fields.
Detect an edited policy file and reject/restore it, record the attempt, and
queue the corresponding central audit event.

These controls constrain the legitimate agent and administrative paths. They
cannot guarantee invulnerability when an attacker controls the agent binary,
trusted keys, kernel, or storage itself. Present a tamper event, invalid policy,
and missing contact separately; do not claim cryptographic proof that the
running process remains trustworthy.

When disconnected, use the last valid policy under its defined validity and
offline rules. Expired/invalid authorization restricts active response while
usable detection continues. An online central round trip must not be required
for every already-authorized local detection decision.

## Agent Removal Policy and Auditing

Support allow, approval_required, and deny in supported management/removal
paths. Audit the request and its policy result. For managed removal requiring
approval:

```text
removal requested -> central durable audit ACK -> authorization
                 -> removal started -> actual result report
```

Do not report removal completed before it succeeds. Package hooks and the
future installer/removal wrapper follow the same policy. An upgrade is a
separate lifecycle operation and must preserve identity and evidence.

Offline removal normally waits for required acknowledgement/authorization.
The emergency one-time removal path below is an explicit exception so access
to a broken host does not depend indefinitely on central availability.

### One-time removal approval and emergency recovery

User requirement added 2026-11-16: enroll removal authentication during initial
installation and retain an administrator-controlled last-resort removal path.
The intended user experience is entering a one-time removal authorization.
The recommended implementation has two complementary paths:

- Online: a signed, single-use central removal grant bound to agent identity,
  enrollment generation, a fresh local challenge, action `uninstall`, grant ID,
  and expiry. Only verification public keys are needed on the agent. The
  central operator can additionally use TOTP/MFA to authorize grant issuance.
- Offline emergency: independently generated high-entropy per-host recovery
  codes bound to the same enrollment generation. The administrator keeps the
  original codes outside the monitored host; the agent stores only protected
  verification values, never the recoverable plaintext codes.

Initial authenticated enrollment provisions the verification material and
establishes how the administrator securely exports and retains recovery codes.
Do not expose enrollment/recovery secrets in command arguments, logs, events,
ordinary panel pages, or the repository. Removal accepts codes via a protected
interactive prompt or equivalent protected input.

Emergency removal requires local administrator access plus a valid host recovery
code and remains available despite the ordinary deny/approval_required policy
or a missing central ACK. Routine remote policy updates cannot silently remove
this installed recovery path. Rotation/revocation uses a separately authorized
recovery-management procedure with an audit record.

Atomically persist consumption and removal intent before destructive teardown.
Consumed approval IDs, challenges, and recovery-code state survive process or
machine restart. Resume an interrupted authorized removal by operation ID;
do not accept its grant for a different operation. Preserve identity and unused
recovery state on upgrade; a deliberate fresh enrollment uses a new generation
and invalidates old grants/codes. Delay repeated failures without permanently
locking an administrator out of all emergency recovery.

Online requests/approvals use the central durable-audit ACK path. Offline
emergency removal records its mode, identity, operation, time, and outcome in a
protected recovery audit location retained beyond normal agent removal, and
attempts delivery when possible. It cannot require an online ACK to proceed.
Do not claim a locally retained record was delivered, or that a future send is
guaranteed after the agent has been removed.

TOTP is a shared-secret mechanism (RFC 6238). Keeping the same seed on the
central server and agent lets a sufficiently privileged local reader generate
matching OTPs. Therefore shared-seed TOTP is not the proposed independent
central authorization mechanism. Normal protocol replay protection also does
not defeat root altering verification/consumption state or restoring a disk
snapshot; these limits remain explicit while TPM/process integrity is deferred.

Universal delivery after forced deletion is not achievable: power loss,
network isolation, SIGKILL, filesystem destruction, or sufficiently privileged
bypass can prevent any final send. Record intent before authorized removal;
retain bounded pending audit data whenever possible. Central heartbeat expiry
detects disappearance but cannot by itself distinguish deletion from an outage.

## Resource Monitoring

- CPU: host/per-core utilization, load, and explicit sampling interval.
- RAM: total/available/used and swap, with cache interpretation visible.
- Disk: filesystem/mount usage, free space, and inode pressure.
- Disk I/O: per-device operations/bytes, busy time and available latency data.
- Processes: boot/PID/start identity, executable, service, UID, CPU, memory,
  process count, and bounded detail pages. Omit argv/environments by default.
- Network: per-interface RX/TX rates/totals, drops/errors, and link state;
  support interface names beyond `eth*`.

Rate metrics use elapsed-time deltas and distinguish reboot, counter reset,
interface recreation, and process exit. Unsupported measurements are unknown,
not zero. Bound polling frequency, process rows, payload size, and retention.
Keep telemetry work independent enough that a large process list cannot stall
security event handling. Support local display and central history, host and
service grouping, and explicit sample/receive times and freshness.

## Policy Contract Outline

```text
identity: policy_id, revision, target_agents/groups, issued_at, validity
authenticity: digest, signer_key_id, signature
requirements: per-rule observation and per-action enforcement capabilities
detection: enabled_rules, origins, scoped_exceptions, risk_model_version
response: mode, action, risk_threshold, min_confidence, scope, freshness,
          degraded_behavior, offline_behavior
agent_protection: uninstall_mode, authorization_and_audit_requirements,
                  enrollment_generation, grant_verification_keys,
                  emergency_recovery_verifiers, consumed_authorizations
monitoring: enabled_metrics, intervals, process_limit, payload/retention_limits
reporting: desired_revision, active_revision, result, failure_reason, applied_at
```

## Implementation and Validation Order

1. Define separate risk/confidence/capability decisions and dry-run evidence.
2. Implement enrollment, central durable history/audit, delivery and heartbeat.
3. Implement signed policy receipt, safe activation and management controls.
4. Validate would_block against canaries and legitimate operational shells;
   add one explicitly scoped actuator and host-specific action probes.
5. Add bounded resource telemetry and central/local monitoring views.
6. Wrap the validated workflows in install/upgrade/removal automation.

Mandatory cases include PM2 deployment exceptions; missing capabilities;
policy tampering/replay/wrong target/expiry; process exit and PID/exec reuse;
central failure; rejected or incomplete removal; upgrade-vs-removal behavior;
offline recovery with deny policy; wrong-host/old-generation/expired grants;
OTP/recovery replay; concurrent consumption and interrupted-removal resume;
recovery-audit retention; counter reset and large process inventories. Preserve current monitor-only
operation until response activation is explicitly authorized.

## Technical References

- https://tetragon.io/docs/concepts/enforcement/
- https://man7.org/linux/man-pages/man2/pidfd_send_signal.2.html
- https://www.rfc-editor.org/rfc/rfc6238.html
