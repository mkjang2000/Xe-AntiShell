# Xe-AntiShell

Xe-AntiShell is an experimental standalone or centrally managed Linux host security agent. The first
version discovers available host capabilities, normalizes process events from
Tetragon or Linux audit, builds local process lineage, detects web-service
descendant shells, and exposes local evidence through a CLI.
The optional local web panel provides an authenticated, read-only view of the
same evidence. The independent
[central project](https://github.com/mkjang2000/Xe-AntiShell-Central) owns server
enrollment, signed policy distribution and fleet evidence storage.

The current implementation is an MVP under active development. It does not
claim complete intrusion detection and cannot make local evidence trustworthy
after full root or kernel compromise.

## Installation

The currently exercised platform is Rocky Linux 9, `x86_64`. Rocky/RHEL-family
8–10 and CentOS 7 are intended targets, with separate OS/kernel validation still
required. The packaged web panel requires systemd 247 or newer; the installer
rejects `--enable-web` on older managers before installing a package.

Choose one installation path from a reviewed checkout:

With no arguments on a terminal, the installer walks through package selection,
standalone or central enrollment, Tetragon collection, optional local monitoring,
and a final review:

```bash
sudo ./install.sh
```

On Rocky Linux 9 or 10 (x86_64), you can start with just the installer:

```bash
workdir=$(mktemp -d) &&
  cd "$workdir" &&
  curl --disable --fail --show-error --location --proto '=https' --proto-redir '=https' \
    --output install.sh https://raw.githubusercontent.com/mkjang2000/Xe-AntiShell/main/install.sh &&
  sudo bash ./install.sh
```

The wizard prefers a compatible local RPM. With no local match or source build,
it downloads the matching RPM from the pinned RPM28 release and checks the
SHA-256 embedded in the installer and the RPM metadata. The wizard asks for
confirmation before installation. A source checkout or full installation bundle
provides the helpers locally. For central enrollment,
paste the complete installation code issued by the authenticated central console.
Input stays hidden. That code carries the central URL, agent ID and pinned public
CA, so no separate CA/token files or recovery path need to be entered. The agent
creates and preserves `/root/xe-antishell-offline-recovery` automatically; copy it
to protected storage outside the monitored host after enrollment.

The existing explicit options remain available for unattended setup:

```bash
# Build a local RPM and install the agent and monitoring panel.
sudo ./install.sh --build --enable-web

# Or build once and install the resulting RPM on another compatible host.
make rpm
sudo ./install.sh --rpm /path/to/built-agent.rpm --enable-web
```

Use the exact RPM path printed by the builder; its name depends on the release,
build host's distribution and architecture.
`--rpm` and `--build` are mutually exclusive. Use `./install.sh --help` for all
options. Installation requires root, RPM and a running systemd manager. Source
building additionally needs Bash, an installed Go 1.22+ toolchain, `rpmbuild`,
systemd RPM macros, make, GNU tar, Python 3.9+ and Git. The builder checks those
tools, uses the local Go toolchain and pinned module checksums, and downloads Go
modules only when absent from the module cache. It does not install dependencies.
Node.js and a C compiler are needed for developer verification, not RPM building.
Install a newer Python on build hosts whose default is older. Installing an
already built RPM through `--rpm` does not require Go; optional Tetragon setup
needs Python3/PyYAML as described below. RPM payload and
runtime dependencies must match the target distribution; for example, the
default EL9 Zstd payload is unsuitable for CentOS 7's older RPM. Build and test
packages separately for each target family.

The installer preserves existing agent configuration, web credentials and recovery
files on retries. New installations start in observation mode. The wizard offers
verified Tetragon setup; scripted setup opts in using `--with-tetragon`.
Audit-rule activation and firewall changes require separate host configuration.
An available agent API confirms startup; it does not confirm event collection.
Check `sudo sentinel capabilities` and the panel's collection status, then
validate detection with a controlled test before considering automatic response.

For complete-code enrollment without prompts, save the code in a root-owned
0600 file and run:

```bash
sudo ./install.sh --rpm ./agent.rpm \
  --enrollment-file /root/xe-installation-code
```

`--recovery-file` can override the automatic default. Do not combine
`--enrollment-file` with the legacy central URL/ID/CA/token options. The encoded
installation code is a credential; do not paste it into command arguments or logs.
It carries the trusted public CA before the first network credential is sent,
and normal certificate-chain and hostname checks remain enabled. Agent private
keys and offline recovery plaintext are generated locally rather than downloaded.

For legacy central enrollment, supply **all five** enrollment options. Keep the token
in a root-owned file with owner-only permissions, and provide a CA obtained
through a trusted channel:

```bash
sudo ./install.sh --rpm ./agent.rpm --enable-web \
  --central https://central.example.internal:9443 \
  --agent-id web-01 \
  --ca-file /root/central-ca.crt \
  --token-file /root/enrollment-token \
  --recovery-file /root/agent-offline-recovery
```

See [central operations](https://github.com/mkjang2000/Xe-AntiShell-Central/blob/main/devdocs/analysis/managed-v1-operations.md) for central
initialization, enrollment, signed policies, removal authorization and recovery.
Central setup is a separate operation; the installer enrolls an agent with an
already initialized server. Preserve the recovery file securely outside the host.

## Root and credential observation

Compatible packaged agents can opt in through Central's privilege profile
(Agent RPM27 / Central RPM14, protocol v0.3.0), independently of web origins.
Central checks the current enrollment's fresh engine capability before issuing
new policy fields. Standalone configuration uses `detection.privilege_rules:
true` and optional `root_exec_alerts: suspicious` or `all`. The default is off.
The source must be an unfiltered JSON Tetragon subscription; only reviewed
argv/environment field exclusions are allowed. A root-owned Unix endpoint and
trusted executable are required for the fixed policy controller.

`suspicious` retains every observed root exec but alerts only when bounded
context factors reach45. `all` also emits low-score routine root alerts. Neither
mode suppresses normal credential-change evidence. These are observations, not
proof of unauthorized escalation: saved/real root restoration, initial user
namespace root gain and unknown/container namespace identity changes have
separate labels. Complete paired snapshots and successful kernel return are
required for a confirmed transition; cached exec credentials are never Before.
Only effective/permitted Capability increases produce current capability rules;
other UID/GID/capability changes remain available as observation history.

The agent controls one compiled monitor-only `commit_creds` policy in a separate
private state directory. Arbitrary remote YAML/commands are not supported. The
engine capability means the profile can be enabled; actual credential monitoring
requires a new complete receipt in the current policy attachment epoch. The
controller retries bounded control failures every 15 seconds. The agent also
resubscribes if its selected Tetragon event stream ends.

The sensor does not observe direct kernel credential writes, all task creation
without exec, or establish container escape from UID0. In-place credential
changes are not general in-process RCE detection. Global hooks and root-exec
storage increase workload and still require per-host measurement. See the
[design](devdocs/plans/privilege-detection.md) and the bounded
[real-kernel proof](devdocs/research/credential-sensor-live-proof.md) for evidence
and remaining validation boundaries. The new rules never terminate processes,
including under another policy's enforce mode.

## Current scope

- Passive host capability discovery for kernel, BTF, audit, Tetragon, IMA,
  TPM, and cgroup evidence
- Tetragon process execution/exit normalization through a `tetra getevents`
  subprocess, without invoking a shell
- Linux audit `SYSCALL`/`EXECVE`/`CWD`/`EOE` assembly for a dispatcher bridge
- Procfs startup snapshot and systemd/cgroup origin enrichment for processes
  that predate the agent
- Boot-scoped process lineage, SQLite evidence storage, and a local
  web-process-to-shell rule
- Opt-in detection-only direct-script and inline-option observations for
  Python/Node/PHP/Perl/Ruby, plus separate fixed-policy file-write/TCP-initiation
  adapters and an explicit installation helper; new kernel policies still need
  target-host attachment and workload validation
- Opt-in global root-execution evidence and paired `commit_creds` observations,
  separating root restoration, initial-user-namespace root gain and
  effective/permitted Capability gain or activation; all six new rules are
  detection-only and require explicit profile opt-in
- HTTP/JSON management API on a mode-`0660` Unix socket
- Authenticated monitoring panel for agent health, findings, candidate events,
  capabilities, and process ancestry
- Separate passive prerequisites and observed runtime capability status, with
  unimplemented observations hidden in a collapsed section by default
- Raw collector payload storage disabled by default, with common secret-bearing
  command arguments redacted before persistence
- mTLS central enrollment, durable delivery with committed ACKs, heartbeat, and
  signed detection/response/monitoring policies with revision rollback rejection
- One-use central removal grants, offline recovery codes, and managed RPM removal
  authorization checks; local management changes require a root Unix peer
- CPU/RAM/filesystem/device-I/O/network/process monitoring without argv/environment
  collection, and service-grouped, cursor-paginated monitoring history

The default and deployed host remain detection-only. An experimental post-exec
SIGTERM actuator requires both `response.allow_terminate: true` locally and a
valid signed `enforce` policy, risk/confidence/capability gates, fresh Tetragon
evidence, and strict live identity checks through pidfd. It refuses uncertain
identity, including source/procfs start-time disagreement. It does not prevent
exec, guarantee process exit, or eliminate a concurrent exec-generation race.
Only controlled test children have been signaled; production auto-response
has not been validated or enabled. Packaging supplies audit plugin and rule
templates under `/usr/share/xe-antishell/audit/`. Installation does not place
them in auditd's active configuration directories. An administrator must copy
and activate them after reviewing their host impact.

For busy audit-based hosts, `collector.audit.include_executables` can retain
only detection-relevant executables and `only_detection_origins` can further
limit durable evidence to configured web service/executable ancestry. Kernel
audit and the dispatcher still observe the configured syscall stream, so audit
loss, backlog, plugin warnings, and host overhead must be monitored.

## Extended web-origin process detection

The default rule detects shells descended from configured web origins. An
optional detection-only profile also reports download tools (`curl`, `wget`),
system-diagnostic tools (`id`, `whoami`, `uname`, `hostname`, `ps`), connection
utilities (`nc`, `ncat`, `socat`), supported inline interpreter options, and
executables or direct interpreter script operands under temporary, memory-backed
or file-descriptor paths. These are reviewable
process observations; they do not establish a successful transfer, an actual
connection, file modification or a confirmed webshell.

Use [the extended collection example](configs/examples/agent-webshell-detection.yaml)
after adjusting exact web-service names and collector paths. The option
`detection.extended_process_rules` defaults to `false`. Enabling it requires
**both** audit and Tetragon `include_executables` lists to be empty, because a
shell-only filter would hide non-shell observations. `only_detection_origins`
can still limit retained evidence to configured web origins. Broader collection
increases storage and central delivery volume; review it per service.

For a managed agent, the verified central policy determines this option. Update
the agent/central software before issuing a policy with the new field. An old
signed policy keeps the previous behavior; it cannot silently enable expansion.
An incompatible collector scope rejects the new policy and preserves the last
approved detector. Expiry retains the approved detection profile with response
disabled.

Extended findings contain fixed observation reasons and additive rule scores,
with the sum capped at 100. Scores are not probabilities of compromise, and
lineage confidence is separate. The panel shows the effective profile, Korean
reasons and detection-only status. **All findings from the extended profile,
including shell rules, are excluded from automatic termination**, even with an
enforce policy and local termination opt-in.

Inline interpreter classification uses either complete exact argv with a
supported option before the first script/module boundary, or a separate
`process.exec_observation` from a reviewed fixed Tetragon policy. Tetragon's
flattened arguments are omitted and never reconstructed. Incomplete audit argv
does not become exact evidence. The fixed policies recognize Python `-c`, Node
`-e`/`--eval`/`-p`/`--print`, PHP `-r`, Perl `-e`/`-E` and Ruby `-e`; observing
an option does not establish valid syntax or successful code execution.
Direct risky script operands currently require exact argv. Ordinary workers
and processes outside configured web origins do not trigger these extra rules.
Legacy shell exceptions only suppress the matching shell behavior; they do not
exempt an independent script, inline-option or temporary-executable observation.

Before queueing, the agent keeps only bounded invocation facts and removes all
argv and raw payloads for the five recognized interpreter families, including
unsupported invocations. Ancestor argv and new operation-event raw payloads are
also omitted. With the optional Tetragon observation subscription, the server
excludes process/parent/ancestor arguments and environments from that stream;
Tetragon still has its own transient argument-selector cache. This is not a
complete command-privacy guarantee: legacy shell `-c` operands retain the prior
argument policy, whose secret-name redactor does not remove arbitrary shell
code. General raw collection remains off by default and should stay off for
routine monitoring.

Run an isolated replay check without installing a package or changing services:

```bash
make static test-detection
```

The checker starts its own temporary agent, socket and database, replays fixed
positive and legitimate-operation metadata, verifies findings and scores, then
removes its resources. It never executes the depicted commands or downloads.
This verifies the executable/persistence path, not real attack detection rates
or live kernel collection. File/network adapters are separately available as
described below; credential observation and multi-event attack-chain correlation
remain future work. Phase 3 existing-process code execution is
[a design deliverable](devdocs/plans/in-process-code-observation.md): no
compile/eval, USDT/uprobe or language-agent sensor has been implemented.

## Commands

```bash
make build

./build/sentineld --config ./configs/sentineld.yaml
./build/sentinel --socket /run/xe-antishell/sentineld.sock status
./build/sentinel --socket /run/xe-antishell/sentineld.sock capabilities
./build/sentinel --socket /run/xe-antishell/sentineld.sock events --limit 20
./build/sentinel --socket /run/xe-antishell/sentineld.sock findings --limit 20
./build/sentinel rules
./build/sentinel observations --limit 20
./build/sentinel capacity
./build/sentinel resources
./build/sentinel managed status
./build/sentinel --socket /run/xe-antishell/sentineld.sock process-tree --pid 1234
```

### Reviewing a host before widening collection

`sentinel rules` and the panel's system view show each built-in rule, its version,
the local or managed policy in effect, and the selected sensor's latest receipt.
Use `--json` before the subcommand for the required evidence fields. Finding
history accepts the same Korean titles shown in the panel.

Compare two **standalone agent YAML configurations** against a normalized JSONL
sample from one host and boot. Each non-blank row requires an event timestamp.
The command uses private in-memory databases and requires no running daemon.

```bash
./build/sentinel rules compare --current configs/sentineld.yaml \
  --candidate configs/examples/agent-webshell-detection.yaml \
  --events testdata/events/web-shell.jsonl
```

The result shows matching input types, findings added or removed, changes to
existing findings, and affected services. Input type presence alone cannot
establish that a sample includes all the evidence a rule needs. The comparison
accepts up to 5,000 observations and 16 MiB. Managed policy approval and live
sensor readiness are checked on the enrolled host.

Review retained file writes and TCP attempts in the panel's event history or
with a service-scoped query. For example, inspect writes to an application tree
and exclude its normal upload directory from review candidates.

```bash
./build/sentinel observations --service example-web.service \
  --protected-dir /srv/app --allowed-dir /srv/app/uploads --limit 50
```

Classification uses the service stored on the event and the observed absolute
path. Only a positive byte count under the protected directory is a candidate.
The path settings apply to this query. TCP results distinguish initiation,
failure and an unknown return. The sample view produces no findings or response
actions.

### Service-specific rule controls

Set `detection.service_rule_controls` in standalone YAML or in a supported
signed policy. Each entry selects one exact service and built-in rule ID.
For example, an approved exception for a deployment can use the following
entry under `detection`.

```yaml
service_rule_controls:
  - service: example-web.service
    rule_id: service-protected-file-write
    mode: suppress_until
    reason: Approved application deployment
    expires_at: 2030-01-01T00:00:00Z
```

The other modes are `enabled` and `disabled` within the active profile.
`sentinel rules` shows the configured controls. Use `sentinel rules compare
--at <RFC3339 timestamp>` for a repeatable expiry comparison.
[Rule policy semantics](devdocs/plans/service-rule-controls.md)

For a Central staged policy rollout, download the comparison input for each host
and use that host's configuration with the same anonymized single-host, single-boot
JSONL sample. The exported input fixes the evaluation time and both policy revisions.
The command produces JSON with rule counts and input digests for the Central console.

```bash
sentinel rules compare --managed-input policy-impact.json --host-config host.yaml --events sample.jsonl > impact-report.json
```

### Service-scoped file and TCP alerts

The following host YAML fragment enables detection-only findings for one
application. Merge the service name into the existing web-services list. On a
managed agent also include the exact name in the active signed policy's
`detection.web_services`. The service name is case-sensitive for these rules.
Omitting `detection.service_observations` from the signed policy uses the local
YAML. A signed array replaces the local scopes in full, and a signed empty
array disables both service rules. A higher revision can omit the field to
restore the YAML scopes. `sentinel rules` shows the source in use. The
`detection.service_observations` capability reports contract support, while
`observation.file` and `observation.network` report sensor evidence.

```yaml
detection:
  enabled: true
  web_services: [example-web.service]
service_observations:
  - service: example-web.service
    protected_dirs: [/srv/app]
    allowed_write_dirs: [/srv/app/uploads, /srv/app/cache]
    allowed_tcp_destinations:
      - cidr: 192.0.2.0/24
        ports: [443]
      - cidr: 2001:db8:10::/64
        ports: [443]
```

Replace the example networks with the application's actual dependencies, including
local proxies or loopback backends when applicable. Each CIDR and its ports form a
single allow entry. Omitting ports allows all ports in that CIDR. An empty list
leaves that rule off. IPv4-mapped IPv6 destinations use the IPv4 policy.
`service-protected-file-write` requires positive bytes under a protected path.
`service-unexpected-tcp-destination` requires an observed TCP initiation to an
address and port outside the service's list. A failed or unknown operation stays
available in observation samples. Both findings link to the original event and
are detection-only even in enforce mode.

Run the example offline against six typed observations. It adds one file finding
and one TCP finding.

```bash
./build/sentinel rules compare --current configs/sentineld.yaml \
  --candidate configs/examples/agent-service-observations.yaml \
  --events testdata/events/service-observations.jsonl
```

Verify each sensor's receipt independently with `sentinel rules`. The optional
Tetragon policies must cover the worker executable and file prefix. See the
[optional sensor setup](#optional-inline-file-write-and-tcp-initiation-policies)
and the [detection design](devdocs/plans/service-observation-rules.md).

Use `sentinel capacity` or the system view to compare today's and yesterday's
UTC event counts and stored JSON bytes. The first day begins at the schema
upgrade. DB, WAL and free disk bytes are separate measurements. Queue depth,
observed high-water mark, drops by cause and submission-to-commit latency
cover the current daemon run. Expired events still referenced by findings are
excluded from the retention backlog. A capped scan shows a lower bound.

Enrolled agents include pending payload bytes and records, the spool limit,
and cumulative delivery losses. A failed send or an ACK with no progress on
an outstanding batch starts a measured interruption. The first advancing ACK
and the ACK that empties the queue close separate timers. Check the interval
loss count along with the drain duration. The latest interruption survives an
agent restart. These metrics reach central through the existing heartbeat
under `status.capability_report.capabilities["storage.capacity"].details`.

RPM builds default to `limits.observation_history_minutes: 60`, including
preserved site configurations that omit the field.
The agent evaluates the complete normalized observation before keeping and
sending a smaller record. It omits raw JSON, command arguments, working
directories and repeated ancestor snapshots. Structured detection evidence,
process identities, finding summaries and scores remain available. Periodic
expiry protects finding evidence and events pending delivery. SQLite reuses
freed pages. An explicit duration overrides the default. An explicit zero
uses the configured `retention_days` and complete observation storage.
Source builds use zero when the field is omitted. The effective duration
and compact-storage status are reported in capacity details.

## Local web panel

The packaged panel is bound to `0.0.0.0:9088`. It is read-only and does not
expose detection policy or response controls. The RPM does not add a firewall
rule; network reachability remains controlled by the host firewall. With
`install.sh --enable-web`, credentials and service startup are handled for you.
For a manually installed RPM, create the initial administrator credentials and
then enable the service:

```bash
sudo sentinel-web init-auth \
  --file /etc/xe-antishell/web-auth.json \
  --initial-password-file /root/xe-antishell-web-initial-password.txt \
  --username admin
sudo systemctl enable --now sentinel-web.service
```

Open the panel using a host address that the firewall permits:

```text
http://MONITORED_HOST:9088
```

The panel defaults to light mode and restores the original diagonal-cut XE
mark. Login and dashboard provide a dark-mode toggle; only an explicit browser
choice is retained. Both palettes preserve readable type, keyboard focus and
high-contrast status labels.

The operator view leads with collection health, reviewable findings, the effective
response mode and issues to check. Korean feature descriptions show one primary
state; original identifiers and diagnostics remain in expandable details. Counts
come from all retained evidence, with rolling 24-hour totals and self-tests
reported separately. Findings can be searched by Korean behavior title or process
path, and self-test history can be included explicitly. The panel remains a
monitoring view; opening a finding does not record a case-resolution decision.

The username is `admin`. Read the generated password on the monitored host,
use it for the first login, and remove the plaintext delivery file afterward:

```bash
sudo cat /root/xe-antishell-web-initial-password.txt
sudo rm /root/xe-antishell-web-initial-password.txt
```

New passwords require at least 8 Unicode characters, including an ASCII lowercase
letter, digit and punctuation character (spaces do not count as punctuation).
Passwords of 8 or 9 characters also require an ASCII uppercase letter. The
maximum remains 1,024 UTF-8 bytes. Existing credentials continue to work without
being checked against newer creation rules.

Port 9088 serves plain HTTP. Do not open it to an untrusted network because the
login password and session would not have transport encryption. The password
hash uses Argon2id, and the root-only authentication file is delivered to the
unprivileged service using systemd credentials. A non-loopback listener
requires the explicit `--allow-non-loopback` process option.

For a non-root local demonstration, use temporary paths and a replay JSONL file:

```bash
./build/sentineld \
  --data-dir /tmp/xe-antishell-data \
  --socket /tmp/xe-antishell.sock \
  --replay "${PWD}/testdata/events/web-shell.jsonl"
```

## Design

- [Concept design](Linux_Host_Security_Platform_Design_v0.1.md)
- [Standalone MVP plan](devdocs/plans/standalone-mvp.md)
- [Monitor-only deployment plan](devdocs/plans/monitor-deployment.md)
- [Central management and installer sequence](devdocs/plans/central-management.md)
- [Managed security policy, response, and monitoring scope](devdocs/plans/security-policy-and-monitoring.md)
- [Execution and I/O observation contract](devdocs/plans/execution-and-io-observations.md)
- [Invocation evidence and privacy boundaries](devdocs/plans/execution-evidence-detection.md)
- [Phase 3 in-process code observation design](devdocs/plans/in-process-code-observation.md)
- [Project structure](Project_tree.md)
- [Managed v1 implementation and accessible panel](devdocs/plans/managed-v1-and-panel-accessibility.md)
- [Central enrollment, policy and removal operations](devdocs/analysis/managed-v1-operations.md)

## Managed installation

`install.sh` installs a supplied, published or locally built RPM, waits for the agent API,
and optionally enrolls and starts the local panel. If the exact package version
is already installed it continues setup without reinstalling it. Incomplete
enrollment options, invalid URL/ID formats, unsuitable file permissions/sizes
and incompatible web prerequisites fail before package changes. Certificate,
token and recovery-code contents are validated during enrollment, after package
installation. A subsequent setup failure is reported without undoing an already
installed package; resolve the reported cause and retry.

The central service has its own project, installer, RPM and service account.
The agent package installs `sentineld`, `sentinel`, `sentinel-web` and the
separately dispatched `sentinel-updater` helper.
The agent RPM owns no central files or service hooks. Distribution RPM triggers
can still consume pending service restart markers from other packages.
The released agent pins the published
[`protocol v0.7.0`](https://github.com/mkjang2000/Xe-AntiShell/tree/protocol/v0.7.0/protocol)
module, which includes optional typed execution/file/network/credential facts and separate
signed package update contracts. Existing
signature domains, stored identities and approved policy bytes are unchanged;
consumers need observation-aware software to display the new fields.

For same-host validation, central defaults to HTTPS `127.0.0.1:9443` and a
credentialed operator API on `127.0.0.1:9444`. A remote-agent deployment needs a
server certificate for its actual access name, an explicitly configured
non-loopback HTTPS listener and separately trusted CA delivery. The operator
API remains loopback-only. The central project provides its own authenticated
fleet console; PostgreSQL, RBAC and automatic certificate renewal remain future work.
Preserve the offline recovery file outside the monitored host.

### Application policies

An enrolled agent can receive one signed policy revision with a host-wide
observation policy and separate policy versions for systemd services. For
example, `nginx.service` can use simulated response while `pm2-app.service`
uses observation. The agent checks process identity and membership in a
cgroup v2 system service before selecting an application policy. Unverified
memberships use the host policy. Enforcement also requires local termination
permission and a successful identity check immediately before sending a signal.
Central reports the signed policy revision confirmed by the agent.

### Managed agent package updates

RPM23 adds an independent updater service. Agents on earlier packages need one
reviewed manual install of an updater-capable RPM; this preserves their existing
enrollment. Afterward, an enrolled agent can receive a central rollout through
separate signed update endpoints on the same pinned mTLS origin. Every release
also needs an independent publisher signature trusted by the agent's built-in
public keys; central deployment authorization alone cannot install an arbitrary
package. The plan binds
the exact EL major/architecture/package, expected installed package, size and
SHA-256; a short install authorization is required after download. The daemon
stages the job, and the separate root service runs the fixed RPM transaction.

`updates.enabled` defaults to true for this packaged feature. Set it to false
in `/etc/xe-antishell/sentineld.yaml` and restart `sentineld` to opt out of new
work; existing outcomes still report. The helper also rereads the file just
before applying. Source/dev builds, unrecognized package/platform state,
missing helpers and custom socket/database paths do not stage new updates.
Update eligibility does not require a working Tetragon or BPF collector.

Central shows the running build separately from the installed RPM. Success
requires the target package and an actual responding daemon with that build
and enrollment; replacing a binary on disk is insufficient. A previously running
collector must also provide actual fresh exec evidence through the same source
after restart. Previously inactive collection is marked `not_applicable`;
an alive API with a dead stream fails the collection check. Interrupted jobs
reconcile without automatically rerunning RPM, downgrading a package, restoring
a database or reenrolling. A failed daemon restart can require local operator
recovery. The check does not certify every sensor or detection rule. See the
[agent update design](devdocs/plans/managed-agent-updates.md) for trust, journal,
retry and validation boundaries.

Fresh installations on SELinux-enforcing hosts should use the verified RPM 33
or a later release with the corrected updater unit. For existing hosts where
SELinux refused the RPM scriptlet transition, use the existing administrator
or configuration-management channel to apply the verified RPM 33 once.
`scripts/bootstrap-rpm-updater.sh` checks the target, package digest and
updater unit before installation. See the [bootstrap procedure](devdocs/plans/managed-agent-updates.md#selinux-rpm-scriptlet-transition).

### Migrating an earlier bundled installation

Packages through `0.1.0-15` owned the central binary and service too. When such
a host has an initialized or enabled central service, the agent installer
refuses an agent-only upgrade. Back up both databases consistently and preserve
PKI, credentials and local unit overrides. Then install the separately built
agent and central RPMs in **one** transaction:

```sh
sudo systemctl stop sentinel-central.service
sudo rpm -Uvh ./xe-antishell-0.1.0-16.el9.x86_64.rpm \
  ./xe-antishell-central-0.1.0-1.el9.x86_64.rpm
sudo systemctl daemon-reload
sudo systemctl enable --now sentinel-central.service
sudo systemctl restart sentineld.service sentinel-web.service
```

The central project retains the existing binary/unit names and state directory.
Keep the current state; run no new `init` or enrollment operation for this
migration. Verify file owners, both services, active policy and delivery ACKs
afterward. See [separation plan](devdocs/plans/central-project-separation.md) for
the ownership, validation and rollback boundaries.

The first central-package install may apply the distribution's unit preset;
explicitly restore the previous enabled state. While central is briefly stopped,
the agent continues local detection and queues records for later delivery.

## Manual audit collection

The RPM supplies a dedicated dispatcher plugin and syscall rule templates. Review
`packaging/audit/` and the host's audit policy before activating them, especially
on busy hosts. After checking for existing files and confirming that these names
do not belong to a prior deployment, activate them as root:

```bash
install -m 0644 /usr/share/xe-antishell/audit/xe-antishell.conf /etc/audit/plugins.d/xe-antishell.conf
install -m 0600 /usr/share/xe-antishell/audit/90-xe-antishell.rules /etc/audit/rules.d/90-xe-antishell.rules
augenrules --check
augenrules --load
auditctl --signal reload

sentinel status
sentinel findings --limit 20
auditctl -s
```

Remove only the `xe-antishell` plugin/rule files and reload auditd to roll back
collection. Preserve `/var/lib/xe-antishell` when evidence must be retained.
Versions through `0.1.0-12` packaged files directly in the active audit paths.
Before upgrading an audit-based deployment, back up and review those files;
RPM may remove unmodified legacy files or preserve modifications as `.rpmsave`.
Verify the host's effective rules and dispatcher after an upgrade. Existing
loaded kernel rules remain until explicitly changed or the host reboots.

## Tetragon process collection

The validated collector version is the official Tetragon v1.8.0 standalone
release. A generic example is in `configs/examples/agent-tetragon.yaml`; review
its service origins and executable path for each host before applying it.
The unit examples are in `packaging/tetragon/`; the external Tetragon
distribution is downloaded separately from this RPM. Tetragon uses a root-only
Unix control socket and local health/metrics endpoints. No tracing or
enforcement policies are installed by the base setup. The additional
monitor-only observation policies below require a separate explicit command.

For an agent that is already installed and enrolled, use the latest installer
and its complete `packaging/` directory:

```bash
sudo ./install.sh --tetragon-only
```

This performs no agent RPM transaction or enrollment. New scripted installations
can add `--with-tetragon` to `--rpm` or `--build`; the terminal wizard defaults to
offering Tetragon. `--tetragon-archive /path/to/tetragon-v1.8.0-amd64.tar.gz`
supplies the same pinned artifact offline. Initial automation supports x86_64
with kernel BTF and a running standard agent unit. The helper installs
Python3/PyYAML through dnf only when missing (EL8 uses Python3.9 packages).

The helper verifies the fixed official SHA256, installs selected binaries and
BPF objects under `/opt/xe-antishell/tetragon/v1.8.0`, and uses a root-only Unix
socket. It checks running health, an actual benign exec PID and fresh agent
collection evidence before success. Failures restore the old collector config
and service state; backups remain root-only. Existing unrelated Tetragon units
or custom agent ExecStart/config overrides require manual integration.
Detection, response opt-in, credentials, database paths and existing filters are
preserved. Repeated healthy setup verifies without restarting services.

[Korean setup and manual procedure](devdocs/analysis/tetragon-installation.ko.md)
includes expected checks and recovery steps. Collection verification does not
establish webshell detection accuracy; run the separate detection scenarios.

The agent receives the process exec/exit stream and keeps source ancestry in a
bounded 50,000-record graph. `collector.tetragon.include_executables` and
`only_detection_origins` restrict durable storage after context processing.
This preserves service ancestry without persisting every process on a busy
host. Tetragon's flattened argument text is omitted rather than reconstructed;
candidate events therefore explicitly lack exact argv evidence.

If the selected Tetragon command exits or reaches EOF, the agent resubscribes
with the same command and filters. Retries start after one second and double
up to 30 seconds. `sentinel status` and the local panel show the latest
interruption, its recovery time and the number of reconnect attempts since
daemon startup. The gap stays open until the new subscription commits a new
retained event to SQLite. A quiet or narrowly filtered host can therefore
show recovery pending while its new stream is running. Events missed during
the outage may be unavailable. Each sensor needs fresh evidence from the new
subscription, and source parse-error counts remain cumulative.

`ACTIVE` in the panel means the agent has received actual selected-source
execution evidence. Passive kernel support remains a separate indication.
Base process collection does not activate file/network observation. Those
capabilities require their own policies and actual accepted source events.
Credential-change and integrity-verification subsystems remain unimplemented.

See [rollout design](devdocs/plans/tetragon-runtime-rollout.md) for the source
switching and validation boundaries.

### Optional inline, file-write and TCP-initiation policies

Update to observation-aware agent software first. With the full reviewed
`packaging/` directory, inspect the helper and explicitly apply it as root:

```bash
python3 packaging/tetragon/observations.py --help
sudo python3 packaging/tetragon/observations.py --apply
```

Without `--apply`, the command only prints usage and changes nothing. It needs
Python 3.9+/PyYAML, x86_64, kernel BTF, and active Tetragon v1.8.0 and agent
services owned by the base installer. Foreign/custom units, conflicting policy
names, changed owned files or configuration require manual review. The manual
Tetragon example is outside this helper's automatic integration scope.

| Observation | Initial scope and result |
| --- | --- |
| Inline option | Fixed interpreter executable names and exact option positions 0–2 after argv[0]; at most two preceding reviewed switches. A script before `-c`/`-e` prevents the match. Three preceding switches are outside this policy's coverage. |
| File write | Fixed executable-name suffixes, regular files and selected path prefixes at `vfs_write`; positive return means bytes written, zero no data, negative failed, missing unknown. |
| TCP connect | The fixed executable set at `tcp_v4_connect`/`tcp_v6_connect`; zero means initiated, negative failed, missing unknown. It does not prove an established connection or delivered traffic. |

The kernel executable set includes recognized web workers, the five interpreter
families, Java/.NET, shells and selected I/O tools, with trusted installed
canonical version names. Runtime selection checks executable-name suffixes,
not a binary digest or a pinned executable directory. Arbitrarily renamed/custom
binaries are outside the initial scope. Default file prefixes are `/tmp/`,
`/var/tmp/`, `/dev/shm/`,
`/var/www/` and `/srv/`. Repeat `--file-prefix /absolute/directory/` to replace
that set; `/tmp/` is required for the private write probe. This does not cover
all writev/mmap/io_uring writes, UDP, file contents or packet payloads. Kernel
selection is followed by a separate agent web-origin retention check; observing
a tool alone is not a file/network event or a maliciousness finding.

The inline policy's three-position bound keeps its six Equal-filter maps within
Tetragon v1.8.0's eight-slot string-map capacity. It does not impose that bound on
the independent bounded exact-argv/audit classifier. The helper verifies zero,
one and two approved preceding switches, and verifies that script-before-option
and three-switch beyond-bound invocations produce no matching policy claim.

The helper adds owned monitor-only policies, configures a subscription that
excludes argv/environments, and may restart the agent when that subscription
changes. It checks loaded hooks, benign positive/script-before-option probes,
a private one-byte write and loopback TCP initiation with matching process
identity. Missing runtimes and unavailable IPv6 remain partial/unverified;
IPv4 coverage can remain available. Ownership and measured scope are recorded
in root-only `/opt/xe-antishell/tetragon/observations.json`; that file alone
cannot activate the agent's runtime capabilities. Review `sudo sentinel status`
and `sudo sentinel capabilities` for actual receipt and health.

Failures attempt to remove newly added owned policies and restore previous
files, subscription and agent state, retaining root-only diagnostic backups.
Repeating an unchanged verified scope avoids unnecessary changes; changing an
existing scope requires manual review. Synthetic and mocked tests are supplemented
by isolated live validation on EL9 kernel `5.14.0-687.66.1.el9_8.x86_64`: all eleven
monitor policies loaded, installed Python/Node/PHP/Perl inline positive/negative
probes passed, and a one-byte write plus IPv4/IPv6 loopback initiation were observed.
Ruby was not installed. This verifies that host and those paths; other kernels,
all I/O methods and sustained production load remain unverified. Validate each
target's coverage and performance. The helper does not enable detection rules
or automatic termination.

See the [Korean application procedure](devdocs/analysis/tetragon-installation.ko.md)
and [pinned-source coverage review](devdocs/research/tetragon-observations.md).

## Development validation

Publisher keys stay outside the central service's state and the agent RPM.
See [release building, independent signing and GitHub publication](devdocs/analysis/release-signing.ko.md)
for the unsigned CI build and developer-side signing/publishing workflow.

```bash
make verify        # source/scripts/UI, vet, race tests, static binaries, isolated replay
make check-source  # review source candidates without printing secret values
make rpm           # create one local RPM under dist/rpm; no host installation
```

`make verify` requires Go 1.22+, Git, Python 3.9+ with PyYAML, Node.js and a C compiler for Go's
race detector. It also tests the independently tagged `protocol/` module. GitHub
Actions runs the same command with Go 1.22 and the current stable Go release.
Released builds pin the published protocol through go.mod/go.sum and do not
need the central project's source tree or a sibling-directory replace. The RPM
builder explicitly disables development workspaces and refuses to overwrite an existing output;
choose `RPM_OUTPUT_DIR=/some/new/directory make rpm` or explicitly use the
builder's `--force` option when replacing an artifact is intended.

To exercise two isolated agent services against an independently built central
binary, run the optional cross-project integration check:

```sh
XEAS_CENTRAL_TEST_BINARY=/path/to/Xe-AntiShell-Central/build/sentinel-central \
  go test -race ./internal/agent -run TestIndependentCentralWithMultipleAgents -v -count=1
```

It uses temporary state, synthetic process observations and loopback ports. It
checks enrollment, scoped policy/history, central interruption, durable replay
and deduplication without connecting to the installed services. Separate-host
kernel/collector testing remains a distinct pilot step.

Rocky Linux 9.8 audit/Tetragon collection and RPM/systemd behavior have been
exercised on a live host. Rocky 8/10, CentOS 7, and SELinux Enforcing still need
their own VM validation. The current web unit uses systemd credentials and
therefore requires a separate CentOS 7 compatibility unit before that panel can
be supported there. A container cannot validate an older distribution's kernel
behavior because it shares the host kernel.

## Repository preparation

Host-specific configuration in `configs/hosts/`, live installation/validation
notes, credentials, databases, tool state and build outputs are excluded from
Git and the builder's source archive. Shareable examples live in
`configs/examples/`. The source check rejects private artifacts and broken local
Markdown links, including links into ignored files. Optional site-specific
literal patterns can be placed one per line in the ignored
`.local/private-source-patterns.txt`; matches report locations without values.

The source repository is [mkjang2000/Xe-AntiShell](https://github.com/mkjang2000/Xe-AntiShell).

## License

Xe-AntiShell's own implementation is licensed under the [MIT License](LICENSE).
The licenses of included Go libraries and runtime code remain applicable;
see [third-party notices](THIRD_PARTY_NOTICES.md). Source archives and RPMs
include those notices and upstream license texts.

Tetragon is installed separately and accessed through the external `tetra`
process. Its distribution and eBPF components retain their upstream licenses;
the agent's MIT license does not change them. This repository does not bundle
Tetragon or contain custom eBPF programs.
