# Runtime Capability Reporting and Tetragon Rollout

## Purpose

Make the monitoring panel distinguish host prerequisites, implemented agent
features, and observed runtime operation. Install the official Tetragon release
on a validation host and verify passive process telemetry and detection end to end.

## Scope and Completion

- Preserve passive capability state/reason and add implementation and runtime
  evidence fields. Runtime state must not be inferred from binary presence.
- Hide planned agent functionality inside a closed-by-default details section.
  Keep unavailable host hardware and inactive installed collectors visible.
- Treat IMA/TPM availability as prerequisites, not completed integrity checking.
- Install a pinned official Tetragon artifact with its published checksum.
- Bind Tetragon control API to a root-only Unix socket; no public control API.
- Enable process exec/exit and process credentials. Load no response or
  enforcement policies. Environment-variable collection remains disabled.
- Validate actual eBPF attachment, source events, origin attribution, credentials,
  candidate detection, negative control, health, and data-volume bounds.
- Switch one active process source only after testing; retain a documented
  audit fallback without two duplicate authoritative process streams.

## Interfaces

Capability gains additive `implementation`, `runtime_state`, `runtime_reason`,
and `verified_at` fields. Runtime values are active, available, unverified,
inactive, and error. Existing clients can continue reading state/reason.
Reports returned to API callers are cloned before overlaying runtime evidence.
The UI preserves the expansion choice while polling.

## Failure Handling

Failure to load eBPF or connect to the event socket leaves audit in operation.
An exited or malformed source stream must appear as an error rather than an
active green capability. Collector start alone does not prove event coverage.
Keep source parameters bounded and raw events disabled. Preserve source
credential ambiguity instead of converting missing EUID to UID 0.

## Validation

Use unit/race/vet/static checks and RPM/unit verification. On the host, inspect
Tetragon sensors and counters, then run hardened non-root positive/negative
canaries with fixed `/bin/sh -c /usr/bin/true` payloads. Confirm the new source,
finding, and capability status through CLI and authenticated panel API. Inspect
resource usage and retention growth. Document the exact version, artifact
digest, limits, and rollback commands under devdocs/analysis.
