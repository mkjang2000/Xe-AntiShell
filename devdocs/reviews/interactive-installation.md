# Interactive installation review

## Behavior and compatibility

No-argument terminal execution uses a separate Korean wizard. Explicit RPM/build,
legacy enrollment and local web options retain their behavior. A complete code
can also be supplied through `--enrollment-file`. Code delivery includes public CA
trust before any network secret is sent; TLS verification and existing managed-v1
identity, policy and recovery contracts remain unchanged.

## Security corrections

- Hidden input disables shell tracing and automatic variable export.
- Original terminal attributes are restored on normal completion and interrupts,
  including cancellation before or during a partial paste. Ctrl-D cancels.
- Credential files use private temporary paths and are removed on exit. Durable
  recovery files survive failures and retries; secret values stay out of argv,
  environment, console diagnostics and repository candidates.
- Installation codes are bounded and strictly decoded, rejecting duplicate or
  unknown JSON fields, malformed CA/URL/identity, expired trust and credentials.
- Central verifies its configured enrollment hostname and CA before issuing codes,
  stores only the enrollment-secret hash, and keeps issue responses no-store.
- Secret dialogs clear memory/DOM on close and pagehide; stale clipboard callbacks
  and queued native close events cannot restore or erase another issue result.

## Validation performed

- Both projects: published protocol v0.1.1, source guards, installer/archive mocks,
  formatting, vet, Go race tests and static builds.
- Wizard: real PTY paths for standalone/central/web/source/manual RPM, cancellation,
  EOF, oversized input, enrollment failure, signal/partial paste, terminal restore
  and automatic-export environments; all system mutations are mocked.
- Existing agent/independent central multiple-agent integration passed, as did all
  pre-existing wire/signature compatibility fixtures.
- Rocky Linux 10.3 x86_64 container: native EL10 RPM build, dependency dry-run and
  installation, RPM verification, installed CLI startup and systemd unit syntax.
- Installed EL10 binaries passed 16 replay scenarios (six observations and ten
  negative/uncertain cases). Two isolated agents enrolled using console-issued
  complete codes, retained their identity/recovery on retry, and delivered
  authenticated heartbeats without exposing credentials in status.
- Central console JavaScript tests and real Chromium issue/download/clipboard/
  close checks passed.

## Practical limits

Containers share the existing host kernel. EL10 userspace checks do not validate
actual Rocky10 eBPF attach, SELinux enforcement, reboot ordering or either target
machine's workload. Tetragon installation/audit activation and real collection
checks remain explicit host setup. The wizard does not activate enforcement.
The operator must keep an off-host backup of the locally generated recovery file.
