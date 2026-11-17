# Monitor-Only Host Deployment

## Purpose

Install Xe-AntiShell on the current Rocky Linux 9 host as a detection-only
service. The deployment must collect real process execution events and produce
web-descendant-shell findings without terminating, suspending, or otherwise
modifying application processes.

## Completion Criteria

- `sentineld` starts automatically and remains queryable over its local Unix
  socket.
- Existing long-running web and application processes are available to the
  lineage engine without restarting those services.
- The audit dispatcher bridge recovers when `sentineld` is unavailable during
  boot or restart.
- Existing audit configuration and plugins remain intact; Xe-AntiShell uses
  separately owned plugin and rule files.
- A controlled, non-destructive web-to-shell test produces a finding.
- No active-response or process-signal path is enabled or installed.

## Current Structure

The standalone MVP already supports Linux audit record assembly and finding
generation. It does not install audit rules, and its dispatcher bridge did not
retry after an initial local API failure. Its in-memory lineage was restored
only from previously stored agent observations, so parents that predated the
first agent start were absent.

## Design

### Process bootstrap

A Linux procfs snapshot reader seeds the in-memory process graph at startup.
It records only the metadata required for lineage: PID, PPID, executable,
credentials, boot-scoped key, and start time. It does not read process
environment data or command-line arguments. Individual processes that exit or
become unreadable during the scan are skipped.

### Audit bridge recovery

The audit plugin continuously drains its standard input. A local API failure
drops the affected record, enters bounded exponential backoff, and later retries
new records. A transient daemon restart therefore causes an explicit telemetry
gap rather than a permanent loss of all future records or backpressure against
auditd. Queue pressure and outage drops are emitted as rate-limited plugin
warnings, followed by a recovery message.

### Audit ownership

Packaging supplies inert templates under `/usr/share/xe-antishell/audit/`.
After host review, the administrator copies them into dedicated paths under
`/etc/audit/plugins.d/` and `/etc/audit/rules.d/` and activates them. Installation
never overwrites `auditd.conf`, the primary rules file, or another plugin.
Packages through `0.1.0-12` used the live audit paths directly; an upgrade must
review legacy file removal or `.rpmsave` preservation and the still-loaded rules.
The deployment uses success-only `execve` and
`execveat` rules for both supported architectures and remains monitor-only.
The host policy persists only configured shell executable basenames whose
systemd/cgroup origin or live ancestry matches a configured web origin after
audit records have been assembled. This keeps the evidence database focused on
rule candidates while audit loss and host overhead remain independently
observable. Allowed-pair candidates remain durable even when they do not emit
a finding.

### Durable process bounds

Linux audit does not supply a process-exit stream. Live procfs is therefore the
authoritative restart snapshot; stale durable audit rows are only a fallback
when procfs cannot be read. Retention removes bounded batches of expired
process rows only when no retained event or finding still references them.

## Change Scope

- Add a procfs snapshot module and agent startup integration.
- Make audit forwarding recover after local socket failures.
- Add audit plugin/rule packaging and deployment documentation.
- Expand monitor-only web runtime names using observed host workloads.
- Do not add or enable active response.

## Data Flow

```text
startup procfs snapshot -> in-memory lineage

kernel audit exec event
-> auditd
-> sentinel audit-plugin
-> sentineld Unix socket
-> event normalization and durable storage
-> lineage update
-> monitor-only detection and finding storage
```

## Failure Handling

- Procfs per-process races are skipped; failure to open procfs is reported and
  leaves the agent degraded rather than fabricating lineage.
- Dispatcher failures use bounded backoff and keep consuming audit input.
- Queue and kernel audit loss counters are checked after deployment.
- Audit rules and plugin files have an explicit removal-and-reload rollback.
- A failed end-to-end finding test stops deployment validation; it never causes
  automatic response to be enabled.

## Compatibility / Impact

- The current host is Rocky Linux 9.8 with auditd 3.1.5 and SELinux disabled.
- Global exec auditing can increase audit volume and CPU use. Post-install
  measurements determine whether audit remains suitable or Tetragon should
  replace it.
- CentOS 7 and Rocky 8/10 require separate packaging and runtime validation.
- Container processes visible in host procfs can contribute lineage, but
  container identity and cgroup-aware policy are deferred.

## Validation Plan

1. Run unit, race, vet, and static-build validation.
2. Validate the procfs snapshot against controlled fixtures and the live host.
3. Verify the audit plugin reconnects after an unavailable local socket.
4. Install binaries, configuration, and service without restarting web
   services.
5. Add the dedicated audit files, load them, and verify audit kernel loss and
   backlog counters.
6. Execute a controlled web-parent-to-shell test and confirm the resulting
   event, lineage, and finding through the CLI.
7. Observe daemon, audit queue, event rate, and findings before considering any
   future dry-run response mode.

### Controlled detection canary

Use a negative control first. This executes a harmless shell under an
unregistered service origin and must not create an event or finding:

```bash
systemd-run --unit=xeas-negative-selftest.service --wait --collect --quiet \
  --property=User=nobody --property=Group=nobody \
  --property=PrivateNetwork=yes --property=PrivateTmp=yes \
  --property=NoNewPrivileges=yes --property=ProtectSystem=strict \
  --property=ProtectHome=yes --property=CapabilityBoundingSet= \
  /usr/bin/python3 -c \
  'import subprocess; subprocess.run(["/bin/sh", "-c", "/usr/bin/true"], check=True)'
```

Then use the configured positive-control origin. It must create one
`web-descendant-shell` finding:

```bash
systemd-run --unit=xeas-detection-selftest.service --wait --collect --quiet \
  --property=User=nobody --property=Group=nobody \
  --property=PrivateNetwork=yes --property=PrivateTmp=yes \
  --property=NoNewPrivileges=yes --property=ProtectSystem=strict \
  --property=ProtectHome=yes --property=CapabilityBoundingSet= \
  /usr/bin/python3 -c \
  'import subprocess; subprocess.run(["/bin/sh", "-c", "/usr/bin/true"], check=True)'
```

Verify the result through both `sentinel findings` and the web panel, then
confirm `Dropped=0`, `Parse errors=0`, audit `lost=0`, and audit `backlog=0`.
The canary creates a durable validation finding by design.

## Rollback

Stop and disable `sentineld`, remove only the Xe-AntiShell audit plugin and rule
files, reload audit rules/auditd, then remove Xe-AntiShell binaries, unit,
configuration, socket, and state only if evidence retention is no longer
required. Existing audit files and web services are not modified.
