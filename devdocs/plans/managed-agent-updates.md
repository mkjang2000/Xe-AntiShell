# Purpose

Allow an enrolled RPM agent to apply a centrally selected agent package through
a bounded signed workflow. The central service stores releases, operator rollout
decisions and per-enrollment jobs. The agent downloads and journals; a separate
root service applies one package. This does not enroll an agent, enable response,
activate Tetragon policies or execute a remotely supplied command line.

# Current Structure and Contract

`protocol v0.2.0` uses update wire version 2. It requires a publisher-signed
release manifest in addition to independent update-plan and update-install
domains under the existing pinned deployment/policy key. Existing policy bytes
and heartbeat fields remain unchanged. Update traffic uses the enrolled mTLS identity:

- `POST /v1/update/status`: observed inventory and local support/opt-out state.
- `GET /v1/update`: an enrollment-bound signed plan or no content.
- `GET /v1/update/artifacts/{sha256}`: a same-origin bounded package stream.
- `POST /v1/update/claim`: a short signed install authorization after download.
- `POST /v1/update/report`: ordered durable reports with exact retry bytes.

The plan binds job/rollout IDs, a separate per-enrollment revision, validity,
release SHA-256/size/EL family/major and exact RPM name/epoch/version/release/arch,
plus the expected installed package. The publisher separately signs the artifact
name, exact package/platform, hash, size and publication time. The agent and
helper trust only publisher public keys compiled into the shared protocol;
central policy, uploaded JSON and host configuration cannot add a publisher key.
A valid deployment signature alone cannot authorize an arbitrary RPM.
The install authorization binds the plan
digest and exact enrollment/job/revision. It is verified again immediately
before mutation. The central currently issues short leases; no lease permits
arbitrary RPM flags, shell commands, a different URL or another package name.

# Modules and Data Flow

```text
managed update worker
→ inventory of running build and installed RPM
→ verify publisher manifest and signed deployment plan against separate keys
→ root-only bounded download, exact size/SHA-256 and RPM header checks
→ durable downloading/ready reports, central ACKs in sequence
→ central install claim and signed authorization
→ atomic local authorized job
→ fixed systemctl start --no-block sentinel-updater.service
→ independent helper revalidates publisher, local opt-out, current identity/key and job
→ RPM transaction test and expected installed-package recheck
→ final deployment/publisher/lease verification after all blocking reads
→ fixed rpm -Uvh, independent daemon restart and actual API version check
→ same-source fresh execution receipt when collection was previously running
→ durable result, resumed agent sends ordered reports until ACK
```

- `internal/buildinfo` and RPM/Makefile flags identify the running binary,
  including nonzero epoch. RPM's installed-package database is observed
  separately. Replacing files does not prove that the new daemon is running.
- `internal/managedclient/updates.go` reuses pinned mTLS and redirect refusal,
  with a separate five-minute stream deadline and 64 MiB maximum. No full RPM
  is buffered in memory. Responses and raw command stderr are never diagnostics.
- `internal/updates` owns platform/header validation, the private journal,
  download staging, recovery and the independent apply operation.
- `internal/agent/managed_update.go` adds a separate 15-second worker. Failures
  do not clear unrelated policy/delivery errors or change heartbeat contents.
- `cmd/sentinel-updater` is a fixed root-only invocation with no arguments.
  Its systemd unit has no restart policy and is dispatched only for a staged job.
  The daemon's `ProtectSystem=strict` sandbox remains in place.

# Local State and Trust

`/var/lib/xe-antishell/updates` is root-owned `0700`. The `0600` journal contains
only signed plans/authorization, public pinned identity and bounded reports; it
does not duplicate publisher private keys, CA private keys, client private keys
or recovery credentials. Publisher private signing operations remain outside
the agent and central deployment service's runtime authority.
The root-only local management action `update-identity` reads current durable
enrollment/public trust instead of a cached snapshot. The helper compares it
with its local job before both the transaction test and actual install.

State writes use temporary files, file sync, same-directory rename and directory
sync. Separate nonblocking state, worker and apply locks prevent stale writes,
parallel downloads and repeated package transactions. Paths, ownership, modes,
symlinks and hard links are checked. Private abandoned download/journal
temporaries are cleaned under the appropriate locks. Retention is one artifact,
one current job and one orphan journal; a simultaneous new download can consume
another 64 MiB. Disk/permission failures prevent installation.

The local job also captures the actual selected collector, whether that known
source was running, whether exec receipt was previously verified, the previous
daemon start time and capture time. An unavailable baseline API causes staging
to wait rather than inventing a not-applicable collection result. A running
source that has not yet produced its first exec still requires a post-update
check.

Reports have monotonic sequences and fixed timestamps retained across retries.
The agent flushes downloading/ready reports before requesting an install lease.
The helper can append installing/results while the daemon restarts; the new
daemon then delivers them in order. A lost response repeats identical report
bytes. Central terminal-job late history is acknowledged without reopening the
rollout or changing its current desired head.

# Gates and Failure Handling

`updates.enabled` defaults to true in the updater-capable RPM but acts only
after enrollment. A local false value refuses new work; the helper reloads it
before applying. Previously recorded results still report. A source/dev build,
non-root process, absent helper/unit, unsupported RPM/OS/architecture or custom
socket/database paths reports its reason and cannot stage a new update. The
initial package scope is the fixed `xe-antishell` x86_64 EL package family.
Kernel/BTF/Tetragon support is independent of update eligibility.

The agent accepts a revision once with its immutable plan. The helper validates
both signing authorities, enrollment, current deployment public key, expiry, exact expected package,
platform, artifact bytes and header again. RPM's transaction test and normal
upgrade behavior reject unmet dependencies and downgrades; neither
`--oldpackage` nor `--replacepkgs` is used. Dependencies are not fetched.
The last lease/publisher check occurs after local configuration, identity and
RPM queries, immediately before launching the actual transaction. Terminal
local results are immutable; recovery reloads the journal under the apply lock
so a stale snapshot cannot change success into failure.

A durable installing claim is never replayed as another RPM invocation. After
interruption, the current package is queried and the actual daemon API/version
is checked. A claimed target already installed and running can reconcile to
success; otherwise the outcome is failed/interrupted without automatic
reinstallation. An unclaimed plan whose expected package changed fails its
precondition. If the installed RPM changed but the old daemon still runs, both
identities remain visible. A helper's own old in-memory build is never reported
as the current daemon version; an unavailable observation is `unknown`.

Successful update verification requires the target installed package and a
responding daemon identifying that target and enrollment. When a known collector
was running before update, success additionally requires the same collector,
a later daemon start, a running error-free stream and fresh collector/exec
runtime evidence in the new daemon lifetime. The bounded 60-second check uses
actual harmless `/usr/bin/true` execs; audit may also use a fixed shell invocation
to fit ordinary executable filters. No event or capability is synthesized.
Dead streams, stale receipts or a changed source produce failed
`collection_check_failed` even when the new API is alive. Reconciliation uses
the same rule and never repeats RPM. Previously inactive/disabled/unsupported
collection is explicitly `not_applicable`, so a recovery update is possible.
These checks establish exec stream operation, not full audit-rule coverage,
optional file/network policy coverage or detection accuracy.
A new enrollment cannot submit the previous enrollment's reports: the
old local job is closed as target mismatch and retained in the orphan journal.

An interrupted RPM transaction is not an atomic filesystem rollback. There is
no automatic package downgrade, database restore or implicit re-enrollment.
The update process preserves normal RPM `%config(noreplace)` behavior. RPM
scriptlets and generic distribution triggers can restart services, including
pending work from other packages; the workflow does not promise that unrelated
services are unaffected. The updater unit is not restarted or stopped during
its own RPM upgrade; removal alone may stop it. Loss of the daemon or remote
management can require an operator's local recovery.

# Compatibility and Validation

Agents through RPM22 do not contain the worker/helper and need one reviewed
manual bootstrap install of RPM23 or a later updater-capable release. The
bootstrap preserves existing enrollment/configuration. New endpoints returning
404/501 are treated as unsupported by the agent; old strict heartbeat decoders
remain compatible. Published protocol modules are pinned without a local replace.

Unit tests use temporary private directories, synthetic packages, in-memory TLS
and fake RPM/systemd runners. They cover exact retry/ordering, interrupted
transactions, installed/running divergence, opt-out, identity/key changes,
revision conflicts, hash/size/header/platform gates, lease expiry before and
after the transaction test or during a final blocking query, and unsafe file
metadata. Publisher tests reject unknown keys, altered manifests and a forged
publisher signature made with a valid deployment key, including an independent
helper check at the final RPM gate. Package-build tests check
that the helper unit enters only the public source archive. Actual RPM changes
and systemd activation require a separate explicitly authorized isolated test or
host rollout; unit/race tests do not mutate host packages or services.

## Focused validation results

- Published `protocol v0.2.0` is pinned with `GOWORK=off`; `go vet ./...` passed.
- Every Go package, including the separate publisher CLI/package, passed race
  tests. Hostmetrics ran all tests three times in the sandbox; the remaining
  packages ran with the loopback/Unix-socket permissions required by their
  fixtures. The unrestricted run reproduced the documented external IN_OPEN
  interference in the hostmetrics privacy test; no test was removed or weakened.
- `make test-scripts` passed command mocks, PTY checks, 68 Tetragon Python tests,
  RPM source-archive checks and 16 source-check tests. An initial parallel run
  reproduced the existing hidden-input signal timeout; the unchanged sequential
  suite passed.
- All four runtime binaries built statically with injected epoch/version/release/
  architecture. The CLI reported `0.1.0-23.el9.x86_64`. The isolated daemon/CLI
  replay passed 20 scenarios: nine observations and eleven negative controls.
- Publisher, lease-after-blocking-read, concurrent helper/ACK, immutable terminal
  results, opt-out/re-enrollment, stale inventory, same-source collection and
  post-check package-change regressions passed with the race detector.

The checks used synthetic packages and temporary fixture keys. They did not
read the production publisher private key, install a host RPM, invoke a host
updater service or perform a live remote update. Installed RPM/unit validation
and an authorized staged rollout remain separate steps.
