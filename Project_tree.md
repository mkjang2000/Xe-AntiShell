# Project Structure

## Overview

- Project Name: Xe-AntiShell (working name)
- Purpose: Linux host security observation/detection, local monitoring and a managed-agent client
- Repository: https://github.com/mkjang2000/Xe-AntiShell
- Project License: MIT; upstream code retains its own notices
- Main Language: Go
- Runtime: Linux (`amd64` is the initial validated build target)
- Local Database: SQLite (pure-Go driver, WAL mode)
- Main Entry Points: `cmd/sentineld`, `cmd/sentinel`, `cmd/sentinel-web`
- Central Project: https://github.com/mkjang2000/Xe-AntiShell-Central
- Shared Module: `github.com/mkjang2000/Xe-AntiShell/protocol v0.1.1`
- Build Command: `make build`, `make static`, or `make rpm`
- Run Command: `build/sentineld --config configs/sentineld.yaml`
- Test Command: `make verify` (source, shell/UI, vet, race tests, static build)

## Managed Project Structure

```text
Xe-AntiShell/
├── .github/workflows/ci.yml       # Same verification on Go 1.22 and stable
├── cmd/
│   ├── sentineld/                 # Privileged host-agent daemon entry point
│   ├── sentinel/                  # Local CLI and audit dispatcher bridge
│   └── sentinel-web/              # Unprivileged local web panel entry point
├── internal/
│   ├── agent/                     # Pipeline, runtime evidence, Tetragon context/filtering
│   ├── capability/                # Host/kernel feature discovery
│   ├── collector/                 # Tetragon, audit, and replay adapters
│   │   └── audit_argv.go          # Bounded count/index validation for exact exec arguments
│   ├── config/                    # Strict configuration loading and validation
│   ├── detection/                 # Web-origin attribution and opt-in process behavior rules
│   │   ├── classifiers.go         # Exact process/argv/path observations without command inspection
│   │   └── extended.go            # One finding per exec, bounded risk factors, detection-only marker
│   ├── identity/                  # Event and boot-scoped process identifiers
│   ├── hostmetrics/               # Bounded procfs/sysfs resource and counter-delta sampler
│   ├── lineage/                   # Bounded process ancestry and source-context tracking
│   ├── localapi/                  # HTTP/JSON API and client over Unix socket
│   ├── model/                     # Shared core aliases plus agent-only history/UI models
│   ├── managedclient/             # Pinned-CA HTTPS enrollment and mTLS transport
│   ├── procfs/                    # Minimal live process/cgroup snapshot
│   ├── response/                  # Explicit opt-in pidfd post-exec SIGTERM actuator
│   ├── storage/                   # SQLite persistence and embedded migrations
│   └── webpanel/                  # Authentication, monitoring APIs and embedded UI
│       └── assets/                # Shared Korean labels, operator overview, feature states, history/resources/themes
├── configs/
│   ├── examples/                  # Shareable collector/policy examples without host inventory
│   │   └── agent-webshell-detection.yaml # Opt-in full web-origin process collection
│   └── sentineld.yaml             # Example production configuration
├── packaging/
│   ├── install_test.sh            # Installer command-mock checks without host mutations
│   ├── install-wizard.sh          # No-argument Korean TTY setup and hidden installation-code input
│   ├── install_wizard_test.py     # Isolated PTY interaction/privacy checks
│   ├── audit/                     # Opt-in audit plugin and exec-rule templates
│   ├── rpm/                       # RPM package skeleton
│   ├── systemd/                   # Generic agent/web/central units
│   └── tetragon/                  # Reviewed standalone Tetragon/agent overrides
├── testdata/events/               # Controlled events and positive/legitimate process scenarios
├── third_party/licenses/          # Upstream Go/runtime license texts for redistribution
├── protocol/                      # Independently tagged, stdlib-only shared Go module
│   ├── managed/                   # Wire contracts, signatures, removal and recovery primitives
│   │   └── testdata/              # Pre-extraction signed-policy/removal compatibility fixtures
│   └── model/                     # Canonical core events, findings and agent status definitions
├── scripts/
│   ├── build-rpm.sh               # Checked source selection and isolated local RPM build
│   ├── build_rpm_test.sh          # Mocked tools and real source archive checks
│   ├── check-source.py            # Candidate source privacy and documentation checks
│   ├── check-detection.py         # Temporary agent/CLI replay check without live changes
│   └── check_source_test.py       # Isolated Git/archive hygiene regression tests
├── devdocs/plans/
│   ├── git-readiness.md           # Installer, source privacy, Git and validation scope
│   ├── mit-publication.md          # MIT, bundled notices and initial public push scope
│   ├── central-management.md      # Central integration and installer boundaries
│   ├── central-project-separation.md # Separate repositories/packages and safe legacy migration
│   ├── managed-v1-and-panel-accessibility.md # Implemented v1 contracts and QA plan
│   ├── panel-light-angular.md     # Light default, restored mark and angular styling
│   ├── operator-monitor-workflow.md # Operator hierarchy, dense records and plain feature status
│   ├── monitor-deployment.md      # Monitor-only host rollout and rollback
│   ├── security-policy-and-monitoring.md # Managed policy, response, removal, metrics scope
│   ├── standalone-mvp.md          # Detailed MVP design and validation plan
│   ├── tetragon-runtime-rollout.md # Runtime status and eBPF rollout design
│   ├── web-monitor-panel.md       # Local read-only web panel design
│   └── webshell-process-detection.md # Opt-in process rules, privacy and staged validation
├── devdocs/analysis/
│   └── managed-v1-operations.md   # Generic enrollment, policy, removal and trust procedures
├── devdocs/reviews/
│   └── managed-agent-security.md  # Policy/delivery/response boundaries and tests
├── Linux_Host_Security_Platform_Design_v0.1.md
├── README.md
├── LICENSE                       # Project MIT license
├── THIRD_PARTY_NOTICES.md         # Included dependencies and external collector boundaries
├── install.sh                    # Scripted setup or a no-argument TTY installation wizard
├── Makefile
├── go.mod
└── go.sum
```

## Main Execution Flow

```text
sentineld startup
→ strict configuration validation
→ host capability probe
→ live procfs lineage bootstrap
→ collector selection
→ normalized event queue
→ process lineage update
→ local rule evaluation
→ atomic evidence/finding/outbox storage
→ optional guarded post-exec response with durable intent/result
→ Unix-socket API
→ sentinel CLI or sentinel-web

Managed outbox → mTLS sender → central transaction/ACK → outbox cleanup
Central signed policy → verification/revision persistence → atomic detector replacement
Host resource samples + policy/agent status → heartbeat → central agent status
Retained evidence + effective agent policy → read-only operator summary → authenticated monitoring view
```

Audit fallback uses a separate input flow:

```text
auditd dispatcher
→ sentinel audit-plugin
→ sentineld Unix-socket ingest endpoint
→ serial-based audit record assembly
→ common event pipeline
```

## Important Components

### Capability Discovery

- Related files: `internal/capability/`, `internal/model/`
- Responsibility: report passive platform prerequisites as `supported`, `limited`, `unsupported`, or `error`. The agent overlays separate implementation/runtime states and verification times from source observations without replacing passive evidence.

### Event Collection

- Related files: `internal/collector/`
- Responsibility: adapt Tetragon JSON, Linux audit multi-record events, and deterministic replay fixtures to the common event model. Audit mode may filter completed events by exact executable basename and configured detection origin before database ingestion. Only one source owns process lifecycle events at a time.

### Live Process Context

- Related files: `internal/procfs/`, `internal/agent/`
- Responsibility: seed lineage from current processes without reading argv or environments, derive exact systemd service/container scope origins, and reconcile Tetragon source ancestors with bootstrap context. The graph is bounded at 50,000 records and source snapshots cannot revive known exits or overwrite newer PID owners.

### Agent Runtime

- Related files: `internal/agent/`, `cmd/sentineld/`
- Responsibility: select a collector, bound the event queue, normalize and persist events, update lineage, run local detection, and expose explicit health/degradation state.

### Storage

- Related files: `internal/storage/`
- Responsibility: durable events, boot-scoped processes, findings/evidence links, retained-history operator summaries, capability snapshots, schema validation, and restart-safe stream sequence recovery.

### Local Management

- Related files: `internal/localapi/`, `cmd/sentinel/`
- Responsibility: daemon-owned Unix socket, bounded queries, local status/capability/event/finding/process-tree commands, and audit dispatcher forwarding.

### Web Monitoring

- Related files: `internal/webpanel/`, `cmd/sentinel-web/`
- Responsibility: Argon2id administrator authentication, signed sessions, and
  an embedded read-only operator dashboard over the existing Unix-socket API.
  Shared labels, feature presentation, overview, records/resources, navigation
  and theme selection are separate browser modules. Summary counts cover all
  retained evidence; self-tests are separate and explicitly includable. Planned
  observations are collapsed by default. Literal non-loopback IP binding needs
  explicit opt-in; the installed unit binds all interfaces on port 9088.

## Architecture Notes

- The CLI never opens the SQLite database directly.
- Site configuration under `configs/hosts/`, live deployment/validation notes,
  build output, credentials and tool state are local-only and excluded from Git
  and shareable source archives.
- Collectors depend on the common event model rather than storage or detection.
- OS names are informational; runtime probes and collector startup determine available functionality.
- Missing lineage and telemetry remain explicit instead of being inferred as trustworthy data.
- Raw collector payloads are disabled by default and common secret-bearing argv
  values are redacted before persistence.
- Durable source-event and finding identifiers make at-least-once collector
  retries idempotent; stream sequence watermarks survive retention and restart.
- Live procfs state is authoritative on restart; stale audit process rows are
  used only when procfs bootstrap fails and unreferenced expired rows are
  removed in bounded retention batches.
- Tetragon is an external collector adapter, not a hard dependency of the agent core.
- On the validated host, Tetragon provides process exec/exit and source ancestry;
  full stream context is bounded in memory while only configured shell/origin
  candidates and their ancestors are persisted. Flattened Tetragon argv remains
  omitted because exact argument boundaries are not preserved by that source.
- Extended process rules require explicit local/signed-policy opt-in and empty
  executable filters. Web-origin retention remains available. Additive risk
  factors are observations, not maliciousness probabilities; every finding in
  this profile is detection-only, independently enforced by the response layer.
- Audit exact argv requires validated argument counts and positions; incomplete
  records do not become inline-code evidence. File/network observations are
  not inferred from process tool execution.
- The local Unix HTTP/JSON API is separate from the central mTLS protocol.
  Monitoring reads are available to the local socket group; enrollment/removal
  mutations additionally require kernel-verified root peer credentials.
- Central implementation, SQLite store, PKI, account and systemd unit belong to
  the independent central project. The agent RPM manages no central files or
  service hooks. Both projects pin the shared protocol release; no local-folder
  replace is needed for released builds. Bootstrap trust precedes enrollment.
- PostgreSQL, central multi-host web administration, operator RBAC and certificate
  renewal remain future work in that project.
- Approved policies and delivery ACK watermarks survive restarts; removal grants
  and recovery credentials are consumed transactionally with audit obligations.
  Direct root/kernel tampering cannot be prevented by these local controls.
- Process integrity and TPM attestation remain deferred. The deployed host stays
  in observe mode; SIGTERM is experimental, explicit opt-in and conservatively
  refuses unprovable process identity. It cannot prevent exec or guarantee exit.
- Project code is MIT; linked dependencies retain upstream license terms and
  notices included in source archives and RPMs. Tetragon remains external.
- The installer does not certify untested OS support or activate a collector
  solely because the API becomes ready.
