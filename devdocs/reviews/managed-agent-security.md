# Managed Agent Security Review

## Implemented Boundaries

- Enrollment pins the operator-supplied CA and verifies HTTPS hostname, returned
  client key, certificate CN/OU enrollment identity and client-auth usage. The
  CA returned by enrollment cannot replace local trust. Client redirects,
  environment HTTP proxies and unbounded response bodies are disabled.
- A private Ed25519 key and CSR are persisted before network enrollment. Retries
  reuse that identity. The administrative CLI must fsync its random recovery
  code before enrollment; agent state stores only an enrollment-bound verifier.
- Policy and uninstall signatures bind their separate domains, key identifier,
  agent and enrollment. Strict JSON decoding rejects unknown fields. Approved
  policy revisions cannot move backward or change content at the same revision.
- Source event sequence and durable delivery sequence are independent. Evidence,
  findings and an enabled delivery obligation are one SQLite transaction. A
  bounded sender serializes ACKs with administrative flushes. Network failure
  does not block detection.
- An immutable detector snapshot covers an entire event. Startup restores the
  last signed policy before accepting events. Policy expiry retains its approved
  detection scope, disables responses and reports stale policy explicitly.
- Risk score and evidence confidence are separate gates. Required capabilities
  must be implemented, active and verified. Input scopes and collector commands
  remain local; a policy cannot silently claim shells excluded by those scopes.

## Termination Limits

Termination requires an explicit host-local opt-in, signed `enforce` policy,
live Tetragon input and live capability gates. Defaults remain observation.
The actuator sends post-execution SIGTERM through pidfd; it does not prevent
execution and does not guarantee exit. There is no numeric-PID kill fallback.

Before signaling, the actuator checks boot identity, a fresh event, exact procfs
start time, executable, UID/EUID and service twice. PID 1, the daemon and its
current ancestor chain are protected. Missing identity or unavailable pidfd
causes refusal. Nanosecond source timestamps that cannot equal procfs
`btime + USER_HZ start ticks` are conservatively refused.

A pidfd pins a process across PID reuse; it does not pin an exec generation.
A concurrent exec between the final check and SIGTERM remains a limitation.
This actuator must not be described as atomic exec-instance containment.
A durable one-use response claim precedes signaling. After interruption the
action is not repeated; its original result may remain unknown.

## Validation

`go test ./...` and `go vet ./...` passed. Race checks passed for agent, managed
protocol/crypto, HTTP client, response and managed storage. Tests cover wrong
CA/hostname/client identity, tampering, policy rollback/conflicts, expiry,
recovery scope, transactional rollback, independent contiguous delivery, invalid
ACKs, detector replacement and capability/risk/confidence gates.

Signal tests target only child `/bin/sleep` processes created by those tests.
They verify SIGTERM success and survival after invalid-identity refusals.
Production blocking and real agent removal were not exercised by these tests.
TPM attestation, root-resistant tamper prevention, automatic trust/certificate
rotation and pre-execution blocking are outside this implementation.
