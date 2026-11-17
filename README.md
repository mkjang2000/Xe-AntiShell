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
standalone or central enrollment, optional local monitoring, and a final review:

```bash
sudo ./install.sh
```

Keep `packaging/install-wizard.sh` beside the installer in its original directory
structure. The installation bundle includes this helper. For central enrollment,
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
sudo ./install.sh --rpm ./dist/rpm/xe-antishell-0.1.0-17.el9.x86_64.rpm --enable-web
```

The RPM filename depends on the build host's distribution and architecture.
`--rpm` and `--build` are mutually exclusive. Use `./install.sh --help` for all
options. Installation requires root, RPM and a running systemd manager. Source
building additionally needs Bash, an installed Go 1.22+ toolchain, `rpmbuild`,
systemd RPM macros, make, GNU tar, Python 3.9+ and Git. The builder checks those
tools, uses the local Go toolchain and pinned module checksums, and downloads Go
modules only when absent from the module cache. It does not install dependencies.
Node.js and a C compiler are needed for developer verification, not RPM building.
Install a newer Python on build hosts whose default is older. Installing an
already built RPM through `--rpm` does not require Python or Go. RPM payload and
runtime dependencies must match the target distribution; for example, the
default EL9 Zstd payload is unsuitable for CentOS 7's older RPM. Build and test
packages separately for each target family.

The installer preserves existing agent configuration, web credentials and recovery
files on retries. New installations start in observation mode. Tetragon setup,
audit-rule activation and firewall changes require separate host configuration.
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
executables under temporary or memory-backed paths. These are reviewable
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

Inline interpreter classification requires a complete, exact argv and an
explicit supported option before any script/module boundary. The Tetragon
adapter omits flattened arguments, so it cannot provide this signal. Incomplete
or fragmented audit argv is marked unknown and cannot prove an inline-code
invocation. Ordinary Python/Node workers and tools outside configured web
origins do not trigger these extra process rules. Legacy shell exceptions only
suppress the matching shell behavior; they do not exempt a temporary executable
or a distinct non-shell category.

Run an isolated replay check without installing a package or changing services:

```bash
make static test-detection
```

The checker starts its own temporary agent, socket and database, replays fixed
positive and legitimate-operation metadata, verifies findings and scores, then
removes its resources. It never executes the depicted commands or downloads.
This verifies the executable/persistence path, not real attack detection rates
or live kernel collection. File/network/credential observation and multi-event
attack-chain correlation remain future work.

## Commands

```bash
make build

./build/sentineld --config ./configs/sentineld.yaml
./build/sentinel --socket /run/xe-antishell/sentineld.sock status
./build/sentinel --socket /run/xe-antishell/sentineld.sock capabilities
./build/sentinel --socket /run/xe-antishell/sentineld.sock events --limit 20
./build/sentinel --socket /run/xe-antishell/sentineld.sock findings --limit 20
./build/sentinel resources
./build/sentinel managed status
./build/sentinel --socket /run/xe-antishell/sentineld.sock process-tree --pid 1234
```

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
- [Project structure](Project_tree.md)
- [Managed v1 implementation and accessible panel](devdocs/plans/managed-v1-and-panel-accessibility.md)
- [Central enrollment, policy and removal operations](devdocs/analysis/managed-v1-operations.md)

## Managed installation

`install.sh` installs a supplied or locally built RPM, waits for the agent API,
and optionally enrolls and starts the local panel. If the exact package version
is already installed it continues setup without reinstalling it. Incomplete
enrollment options, invalid URL/ID formats, unsuitable file permissions/sizes
and incompatible web prerequisites fail before package changes. Certificate,
token and recovery-code contents are validated during enrollment, after package
installation. A subsequent setup failure is reported without undoing an already
installed package; resolve the reported cause and retry.

The central service has its own project, installer, RPM and service account.
The agent package installs only `sentineld`, `sentinel` and `sentinel-web`.
Agent updates do not restart central, and central updates do not restart the
agent. Both use the published
[`protocol v0.1.1`](https://github.com/mkjang2000/Xe-AntiShell/tree/protocol/v0.1.1/protocol)
module; JSON schemas, signature domains, stored identities and approved
policies are unchanged by project separation.

For same-host validation, central defaults to HTTPS `127.0.0.1:9443` and a
credentialed operator API on `127.0.0.1:9444`. A remote-agent deployment needs a
server certificate for its actual access name, an explicitly configured
non-loopback HTTPS listener and separately trusted CA delivery. The operator
API remains loopback-only. The central project provides its own authenticated
fleet console; PostgreSQL, RBAC and automatic certificate renewal remain future work.
Preserve the offline recovery file outside the monitored host.

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
distribution is installed separately from this RPM. Tetragon uses a root-only
Unix control socket and local health/metrics endpoints. No tracing or
enforcement policies are installed.

The agent receives the process exec/exit stream and keeps source ancestry in a
bounded 50,000-record graph. `collector.tetragon.include_executables` and
`only_detection_origins` restrict durable storage after context processing.
This preserves service ancestry without persisting every process on a busy
host. Tetragon's flattened argument text is omitted rather than reconstructed;
candidate events therefore explicitly lack exact argv evidence.

`ACTIVE` in the panel means the agent has received actual selected-source
execution evidence. Passive kernel support remains a separate indication.
Installing Tetragon does not implement the file, network, credential-change,
or integrity-verification subsystems. Those require their own adapters and
validation.

See [rollout design](devdocs/plans/tetragon-runtime-rollout.md) for the source
switching and validation boundaries.

## Development validation

```bash
make verify        # source/scripts/UI, vet, race tests, static binaries, isolated replay
make check-source  # review source candidates without printing secret values
make rpm           # create one local RPM under dist/rpm; no host installation
```

`make verify` requires Go 1.22+, Git, Python 3.9+, Node.js and a C compiler for Go's
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
