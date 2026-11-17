# Standalone Host Agent MVP

## Purpose

Build the first Xe-AntiShell release as a standalone Linux host security agent.
The agent discovers the host's actual observation capabilities, enables only
usable collection paths, performs local detection, retains evidence locally,
and exposes its state through a local CLI.

Central management and remote delivery are deferred, while event identity and
internal interfaces remain suitable for adding them later.

## Completion Criteria

- `sentineld` and `sentinel` build as Linux binaries.
- Host distribution, kernel, boot ID, BTF, audit, IMA, TPM, and Tetragon
  availability are reported without treating OS name alone as proof of support.
- The daemon selects an available collector or reports an explicit unsupported
  state; it never presents disabled collection as healthy.
- Tetragon and Linux audit process records can be normalized into a common
  event model.
- Process lineage is stored using a boot-scoped identity rather than PID alone.
- A local rule detects a shell descended from a configured web-service process.
- Events, findings, processes, and the latest capability report are retained in
  SQLite and queryable over a protected Unix socket.
- Tests cover normalization, lineage, detection, storage, API behavior,
  malformed input, and degraded capability states.

## Current Structure

The repository initially contains only the v0.1 concept document. There is no
existing implementation or established code pattern to preserve.

## Architecture

```text
Host capability probe
        |
Collector selection
        |
Tetragon stream / audit dispatcher / replay input
        |
Validation and common event normalization
        |
SQLite event persistence
        |
Process lineage -> local detection -> findings
        |
Versioned HTTP/JSON API over Unix domain socket
        |
sentinel CLI
```

The collector, storage, lineage, detection, and API packages have explicit
interfaces. A future remote sender can consume the same normalized events and
durable sequence state without changing collectors or local rules.

## Technology Decisions

- **Language:** Go for daemon, CLI, normalization, detection, and local API.
- **Kernel code:** no custom kernel program in the first slice. Tetragon is an
  optional external producer. Custom eBPF is considered only after Phase 0
  measurements identify a concrete gap.
- **Local API:** versioned HTTP/JSON on a Unix domain socket. It avoids code
  generation during the standalone MVP. Protobuf/gRPC remains a remote protocol
  candidate for the central-management phase.
- **Storage:** SQLite in WAL mode through a pure-Go driver, avoiding a runtime
  dependency on the host's libc or SQLite packages.
- **Configuration:** strict YAML with unknown fields rejected.
- **Packaging:** systemd unit and RPM skeleton. Target-distribution packaging
  validation remains a separate VM gate.

## Capability Model

Every capability is one of:

- `supported`: directly available for the selected implementation.
- `limited`: a useful fallback exists with known coverage limitations.
- `unsupported`: no safe implementation is available.
- `error`: an expected capability failed its probe or operation.

The initial passive probe inspects kernel and host artifacts. Collector startup
is the operational probe: failure changes runtime health to degraded or error.
A harmless eBPF load/attach probe is deferred until the direct eBPF hook set is
selected.

## Collector Selection

1. An explicitly configured replay file is used only for tests and controlled
   demonstrations.
2. A configured Tetragon client stream is preferred on capable hosts.
3. Linux audit dispatcher input is the legacy fallback.
4. If no collector is usable, the daemon remains queryable but reports
   `UNSUPPORTED` instead of claiming active monitoring.

Only one source owns process lifecycle events at a time. The daemon does not
modify global audit rules in this MVP because doing so can disrupt an existing
compliance setup. Rule installation requires a later explicit configuration
workflow.

## Data Model

The minimum durable objects are:

- `events`: normalized event plus bounded source metadata.
- `processes`: boot-scoped process key, parent key, identity, executable,
  credentials, origin, and lineage completeness.
- `findings`: rule, severity, confidence, evidence event, and state.
- `capability_reports`: timestamped platform and feature reports.
- `runtime_state`: local sequence and operational metadata.

Process keys prefer a collector-provided execution ID. Otherwise they use
`boot_id + pid + start time/event time`. A missing parent remains explicitly
incomplete; the agent does not invent ancestry.

## Security Boundaries

- The daemon owns the database and socket. The CLI never opens the database.
- An existing non-socket path is never removed when binding the API socket.
- Inputs have line, argv, raw payload, and query-result limits.
- Raw source payloads are disabled by default and sensitive argv values are
  redacted before persistence; any retained raw payload requires an explicit
  privacy configuration decision.
- Unknown configuration fields fail startup.
- External collectors are never launched through a shell.
- Missing telemetry, parser failures, queue drops, and collector termination are
  surfaced in runtime status.
- This standalone version cannot protect its database after full root or kernel
  compromise; remote durable delivery remains a later security requirement.

## Failure Handling

- Malformed individual records are counted and skipped without stopping the
  collector.
- Storage errors move runtime health to error and stop claims of successful
  processing.
- Bounded queues count drops rather than consuming unbounded memory.
- Collector disconnects create an observable collection gap.
- Database migrations run transactionally and reject a newer unknown schema.

## Compatibility and Impact

- Rocky Linux 9 and 10 are intended full-capability targets when Tetragon starts
  successfully.
- Rocky Linux 8 is probed; audit fallback is expected on its default kernel.
- CentOS Linux 7 is a legacy compatibility target using audit input. The product
  does not imply continued OS security maintenance for this EOL distribution.
- Initial build and test scope is `linux/amd64`. Additional architectures need
  separate collector and packaging validation.

## Validation Plan

Local checks:

```text
go test ./...
go test -race ./...
go vet ./...
CGO_ENABLED=0 go build -buildvcs=false ./cmd/...
```

Privileged VM gates, not reproducible in an unprivileged development container:

- Rocky 9: Tetragon startup, process events, web-to-shell finding.
- Rocky 10: same plus current-kernel compatibility.
- Rocky 8.10: capability result and safe audit fallback.
- CentOS 7.9: static binary execution and legacy audit collection.
- SELinux Enforcing: RPM install, socket/database labels, and systemd startup.
- Kernel update/reboot: boot ID change and capability refresh.
- Event flood/disk pressure: queue drops and storage failure reporting.

## Deferred Work

- Active eBPF attach probing and a direct eBPF collector.
- Automatic audit rule installation or ownership.
- Signed policy/update delivery.
- Remote mTLS sender, durable ACK, central server, and Web UI.
- TPM/IMA attestation verification.
- Response or enforcement actions.
