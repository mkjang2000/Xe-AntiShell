# Purpose

Make a failed first enrollment diagnosable without exposing installation tokens,
recovery codes, private keys, request bodies, URLs, or remote error text.

# Current Structure

The CLI saves a recovery file before calling the root-only Unix API. The daemon
persists a pending key/CSR before pinned-CA HTTPS enrollment. Transport errors are
currently reduced to one sentinel error; failed enrollment is absent from runtime
status and logs. The CLI intentionally suppresses arbitrary API error strings.

# Design and Change Scope

- Classify transport failures into a fixed allowlist in `internal/managedclient`.
  Preserve `errors.Is(err, ErrTransport)` without retaining the original error.
- Record fixed enrollment stage/category descriptions in `ManagedStatus.LastError`
  and a journal warning. HTTP failures expose only a validated numeric status.
- Clear only the enrollment failure on success, including an idempotent retry.
- Preserve the CLI's suppression of arbitrary error text. Its existing instruction
  to check status becomes actionable.
- Keep wire contracts, SQLite schema, credentials, policy and collection unchanged.

# Failure Handling and Compatibility

Distinguish DNS, connection rejection, unreachable network, timeout, permission,
certificate and TLS failures. Distinguish pending identity mismatch and local state
failures from a central request failure. Context cancellation remains detectable.
No automatic trust replacement, pending-key reset, or recovery-file deletion is
introduced. Status is runtime-only and journal warnings survive a daemon restart.

# Validation Plan

- Unit tests for wrapped network/TLS failures and secret-contaminated errors.
- Enrollment failure status and warning redaction; independent error recovery.
- Existing pinned-CA enrollment, lost-response retry and CLI privacy tests.
- Build and EL10 RPM installation/enrollment checks when packaging this change.
