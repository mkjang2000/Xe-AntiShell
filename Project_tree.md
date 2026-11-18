# Project Structure

## Overview

- Project Name: Xe-AntiShell (working name)
- Purpose: Linux host security observation/detection, local monitoring and a managed-agent client
- Repository: https://github.com/mkjang2000/Xe-AntiShell
- Project License: MIT; upstream code retains its own notices
- Main Language: Go
- Runtime: Linux (`amd64` is the initial validated build target)
- Local Database: SQLite (pure-Go driver, WAL mode)
- Main Entry Points: `cmd/sentineld`, `cmd/sentinel`, `cmd/sentinel-web`, `cmd/sentinel-updater`
- Developer Tool Entry: `cmd/xeas-release` (publisher signing tool, excluded from RPM payload)
- Central Project: https://github.com/mkjang2000/Xe-AntiShell-Central
- Shared Module: `github.com/mkjang2000/Xe-AntiShell/protocol v0.3.1`
- Build Command: `make build`, `make static`, or `make rpm`
- Run Command: `build/sentineld --config configs/sentineld.yaml`
- Test Command: `make verify` (source, shell/UI, vet, race tests, static build)

## Managed Project Structure

```text
Xe-AntiShell/
├── .github/workflows/
│   ├── ci.yml                    # Same verification on Go 1.22 and stable
│   └── release-build.yml         # Unsigned EL9/EL10 candidates; no publisher key or release write access
├── cmd/
│   ├── sentineld/                 # Privileged host-agent daemon entry point
│   ├── sentinel/                  # Local CLI and audit dispatcher bridge
│   ├── sentinel-web/              # Unprivileged local web panel entry point
│   ├── sentinel-updater/          # Fixed root-only independent RPM apply entry point
│   └── xeas-release/              # Separate publisher manifest signing/verification CLI
├── internal/
│   ├── agent/                     # Pipeline, runtime evidence, Tetragon context/filtering
│   │   ├── event_normalization.go # Queue-boundary privacy, exact-proof validation and event limits
│   │   ├── operation_events.go    # Typed operation validation and lifecycle-safe context observation
│   │   ├── processing.go          # Durable event pipeline and persistence/response failure separation
│   │   ├── runtime_errors.go      # Independent recoverable operation errors over collector state
│   │   ├── retention.go           # Deferred and paced database maintenance
│   │   ├── privilege.go           # Opt-in engine capability, paired receipt epoch and fixed-policy worker
│   │   ├── managed_worker.go      # Bounded acknowledged delivery bursts and independent control workers
│   │   └── managed_update.go      # Separate update inventory/polling/report worker
│   ├── buildinfo/                 # Injected running RPM epoch/version/release/architecture
│   ├── capability/                # Host/kernel feature discovery
│   ├── collector/                 # Tetragon, audit, and replay adapters
│   │   ├── capability_json.go     # Private pinned-token decode with standard JSON fallback
│   │   ├── audit_argv.go          # Bounded count/index validation for exact exec arguments
│   │   ├── privilege_observation.go # Same-hook credential pairs with kernel task identity
│   │   ├── privilege_credentials.go # Complete credential/capability/namespace decoding
│   │   └── tetragon_observations.go # Fixed-policy inline/file/TCP metadata adapters
│   ├── config/                    # Strict configuration loading and validation
│   ├── detection/                 # Web-origin attribution and opt-in process behavior rules
│   │   ├── classifiers.go         # Process/path observations without command reconstruction
│   │   ├── execution.go           # Code-free exact-argv/policy evidence and runtime-argument removal
│   │   ├── privilege.go           # Global root-exec retention and suspicious/all alert selection
│   │   ├── privilege_credentials.go # Root restoration/gain and capability gain/activation rules
│   │   └── extended.go            # One finding per observation, bounded factors, detection-only marker
│   ├── identity/                  # Event and boot-scoped process identifiers
│   ├── hostmetrics/               # Bounded procfs/sysfs resource and counter-delta sampler
│   ├── lineage/                   # Bounded process ancestry and source-context tracking
│   ├── localapi/                  # HTTP/JSON API and client over Unix socket
│   ├── model/                     # Shared core aliases plus agent-only history/UI models
│   ├── managedclient/             # Pinned-CA HTTPS, mTLS and safe transport diagnostics
│   ├── privileges/                # Strict Tetragon args and root-owned fixed monitor-policy controller
│   │   ├── policy_list.go         # Canonical empty upstream list and duplicate-key-safe decoding
│   │   └── credential-policy.yaml # Compiled commit_creds old/new/TID/start/TGID/return sensor
│   ├── procfs/                    # Minimal live process/cgroup snapshot
│   ├── releasepublish/            # Explicit publisher commands, private-key file safety and manifest handling
│   ├── response/                  # Explicit opt-in pidfd post-exec SIGTERM actuator
│   ├── storage/                   # Serialized SQLite persistence and embedded migrations
│   │   ├── observations.go        # Atomic evidence/outbox save, call-local JSON reuse and bounded writer retry
│   │   └── process_context.go     # Durable operation context merge preserving process lifecycle
│   ├── updates/                   # Publisher/deployment trust, private jobs, RPM apply and collection recheck
│   └── webpanel/                  # Authentication, monitoring APIs and embedded UI
│       ├── password_policy.go     # New-password composition; legacy verification stays independent
│       └── assets/                # Shared Korean labels, operator overview, feature states, history/resources/themes
├── configs/
│   ├── examples/                  # Shareable collector/policy examples without host inventory
│   │   └── agent-webshell-detection.yaml # Opt-in full web-origin process collection
│   └── sentineld.yaml             # Example production configuration
├── packaging/
│   ├── install_test.sh            # Installer command-mock checks without host mutations
│   ├── install-wizard.sh          # No-argument Korean TTY setup and hidden installation-code input
│   ├── install-tetragon.sh        # Explicit collector setup and distribution Python selection
│   ├── install_tetragon_test.sh   # Mocked Python selection/dependency regression checks
│   ├── install_wizard_test.py     # Isolated PTY interaction/privacy checks
│   ├── audit/                     # Opt-in audit plugin and exec-rule templates
│   ├── rpm/                       # RPM package skeleton
│   ├── systemd/                   # Agent/web and separately dispatched updater units
│   └── tetragon/                  # Reviewed overrides plus pinned artifact/config/runtime/rollback helpers
│       ├── observations.py        # Separate explicit --apply entry for monitor-only observation policies
│       └── observation_*.py       # Fixed scope, real probes, ownership and transactional rollback
├── testdata/events/               # Controlled events and positive/legitimate process scenarios
├── third_party/licenses/          # Upstream Go/runtime license texts for redistribution
├── protocol/                      # Independently tagged, stdlib-only shared Go module
│   ├── managed/                   # Wire contracts, signatures, removal and recovery primitives
│   │   ├── updates.go             # Independent signed plan/install lease and separate inventory/report API contracts
│   │   ├── releases.go            # Independently signed release manifest and built-in public publisher anchors
│   │   └── testdata/              # Pre-extraction signed-policy/removal compatibility fixtures
│   └── model/                     # Canonical core events, findings and agent status definitions
│       ├── credentials.go         # Optional paired task credentials, capabilities and user namespaces
│       └── observations.go        # Optional code-free execution/file/network facts
├── scripts/
│   ├── build-rpm.sh               # Checked source selection and isolated local RPM build
│   ├── build_rpm_test.sh          # Mocked tools and real source archive checks
│   ├── check-source.py            # Candidate source privacy and documentation checks
│   ├── check-detection.py         # Temporary agent/CLI replay check without live changes
│   ├── check_source_test.py       # Isolated Git/archive hygiene regression tests
│   ├── build-release-tool.sh      # Build the separate developer publisher CLI
│   ├── sign-release.sh            # Explicit reviewed release-signing entry; not a daemon/RPM hook
│   ├── publish-release.sh         # Local signed public bundle and explicit draft/upload/publication
│   └── publish_release_test.sh    # Mocked publisher/GitHub orchestration without real credentials
├── devdocs/plans/
│   ├── process-observation-clock.md # Lifecycle/observation clock separation and late-event persistence
│   ├── capability-report-consistency.md # Configured collector discovery and independent live evidence
│   ├── tetragon-installation.md    # Optional collector install, verification and rollback design
│   ├── enrollment-diagnostics.md  # Credential-safe failure categories and enrollment status
│   ├── interactive-installation.md # TTY workflow and trusted single-code enrollment
│   ├── rocky10-package-validation.md # EL10 userspace/RPM scope and kernel validation boundary
│   ├── git-readiness.md           # Installer, source privacy, Git and validation scope
│   ├── mit-publication.md          # MIT, bundled notices and initial public push scope
│   ├── central-management.md      # Central integration and installer boundaries
│   ├── managed-agent-updates.md   # Enrollment-bound RPM update staging, apply, identity and recovery
│   ├── agent-hot-path-optimization.md # Constrained-VPS CPU/GC/JSON optimization and correctness gates
│   ├── privilege-detection.md     # Global root and same-hook credential detection/control contract
│   ├── sqlite-startup-stability.md # Serialized SQLite, safe retry, recovery and staggered startup
│   ├── central-agent-updates.md   # Central release catalog, rollout authorization and publisher trust separation
│   ├── central-project-separation.md # Separate repositories/packages and safe legacy migration
│   ├── managed-v1-and-panel-accessibility.md # Implemented v1 contracts and QA plan
│   ├── panel-light-angular.md     # Light default, restored mark and angular styling
│   ├── operator-monitor-workflow.md # Operator hierarchy, dense records and plain feature status
│   ├── monitor-deployment.md      # Monitor-only host rollout and rollback
│   ├── security-policy-and-monitoring.md # Managed policy, response, removal, metrics scope
│   ├── standalone-mvp.md          # Detailed MVP design and validation plan
│   ├── tetragon-runtime-rollout.md # Runtime status and eBPF rollout design
│   ├── web-monitor-panel.md       # Local read-only web panel design
│   ├── webshell-process-detection.md # Opt-in process rules, privacy and staged validation
│   ├── execution-and-io-observations.md # Shared execution/file/network implementation contract
│   ├── execution-evidence-detection.md # Exact invocation facts, privacy and detector limits
│   └── in-process-code-observation.md # Phase 3 runtime-specific design; sensors not implemented
├── devdocs/analysis/
│   ├── managed-v1-operations.md   # Generic enrollment, policy, removal and trust procedures
│   ├── tetragon-installation.ko.md # Existing-agent collector setup and manual procedure
│   └── release-signing.ko.md      # Separate publisher signing and review procedure
├── devdocs/reviews/
│   └── managed-agent-security.md  # Policy/delivery/response boundaries and tests
├── devdocs/research/
│   ├── credential-sensor-live-proof.md # Bounded Rocky9/Tetragon1.8 real saved-root restoration proof
│   └── tetragon-observations.md   # Pinned v1.8.0 source evidence, hook semantics and coverage limits
├── Linux_Host_Security_Platform_Design_v0.1.md
├── README.md
├── LICENSE                       # Project MIT license
├── THIRD_PARTY_NOTICES.md         # Included dependencies and external collector boundaries
├── install.sh                    # Local/build installation and verified release bootstrap for the TTY wizard
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
→ privacy-bounded normalized event queue
→ process lifecycle update or operation-only context merge
→ local rule evaluation
→ atomic evidence/finding/outbox storage
→ optional guarded post-exec response with durable intent/result
→ Unix-socket API
→ sentinel CLI or sentinel-web

Managed outbox → mTLS sender → central transaction/ACK → outbox cleanup
Central signed policy → verification/revision persistence → atomic detector replacement
Central signed update plan → bounded RPM download → report ACKs → short install lease
→ root-only journal → independent updater unit → RPM apply/API version verification → result replay
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
- Responsibility: adapt Tetragon JSON, Linux audit multi-record events, and deterministic replay fixtures to the common event model. Fixed owned Tetragon policies can additionally supply separate inline-option, regular-file-write and TCP-initiation metadata. Audit mode may filter completed events by exact executable basename and configured detection origin before database ingestion. Only one source owns process lifecycle events at a time.

### Live Process Context

- Related files: `internal/procfs/`, `internal/agent/`
- Responsibility: seed lineage from current processes without reading argv or environments, derive exact systemd service/container scope origins, and reconcile Tetragon source ancestors with bootstrap context. The graph is bounded at 50,000 records and source snapshots cannot revive known exits or overwrite newer PID owners.

### Agent Runtime

- Related files: `internal/agent/`, `cmd/sentineld/`
- Responsibility: select a collector, bound the event queue, normalize and persist events, update lineage, run local detection, and expose explicit health/degradation state.

### Storage

- Related files: `internal/storage/`
- Responsibility: durable events, boot-scoped processes, findings/evidence links, retained-history operator summaries, capability snapshots, schema validation, and restart-safe stream sequence recovery. Operation snapshots preserve immutable source fields while a separate durable context merge preserves known exits and observation bounds; retries do not ignore changed source parent/lifecycle identity.

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
- The updater also avoids the daemon database. It rechecks current public
  enrollment trust through a root-authorized Unix API and keeps its bounded
  journal under a separate root-only directory. Existing heartbeat fields and
  policy signatures remain unchanged. A source/dev build cannot apply updates.
- Site configuration under `configs/hosts/`, live deployment/validation notes,
  build output, credentials and tool state are local-only and excluded from Git
  and shareable source archives.
- Collectors depend on the common event model rather than storage or detection.
- OS names are informational; runtime probes and collector startup determine available functionality.
- Missing lineage and telemetry remain explicit instead of being inferred as trustworthy data.
- Raw collector payloads are disabled by default and common secret-bearing argv
  values are redacted before persistence. Known Python/Node/PHP/Perl/Ruby argv
  and raw payloads are removed before queueing after bounded invocation facts
  are extracted. New operation events also discard raw payloads and argv;
  ancestor argv is omitted. Legacy shell `-c` operands still use the existing
  argument/privacy policy and are not covered by whole-runtime removal.
- Durable source-event and finding identifiers make at-least-once collector
  retries idempotent; stream sequence watermarks survive retention and restart.
- Live procfs state is authoritative on restart; stale audit process rows are
  used only when procfs bootstrap fails and unreferenced expired rows are
  removed in bounded retention batches.
- Tetragon is an external collector adapter, not a hard dependency of the agent core.
  The optional installer verifies a pinned upstream archive and actual exec
  observation before switching the existing agent. Installation helpers are
  separate from the privileged daemon and retain rollback backups.
- On the validated host, Tetragon provides process exec/exit and source ancestry;
  full stream context is bounded in memory while only configured shell/origin
  candidates and their ancestors are persisted. Flattened Tetragon argv remains
  omitted because exact argument boundaries are not preserved by that source.
- Extended process rules require explicit local/signed-policy opt-in and empty
  executable filters. Web-origin retention remains available. Additive risk
  factors are observations, not maliciousness probabilities; every finding in
  this profile is detection-only, independently enforced by the response layer.
- Audit exact argv requires validated argument counts and positions; incomplete
  records do not become inline-code evidence. Tetragon inline observations
  require fixed policy/runtime/option proof, not reconstructed flattened argv.
  File/network observations are not inferred from process tool execution.
- The separate observation helper requires explicit `--apply` and an active,
  installer-owned v1.8.0 setup. Kernel selectors bound executable names and file
  prefixes; the agent separately requires configured web-origin retention.
  `vfs_write` does not cover all writes, and TCP connect return zero means
  initiated rather than established. Each capability needs its own actual
  receipt; installation metadata is not runtime activation evidence. New policy
  attachment and workload overhead still require target-host validation.
- Optional privilege rules retain global root executions and same-hook credential
  transitions outside web-origin filters. Their fixed monitor-only policy is
  compiled into packaged agents, controlled through a root-owned Unix endpoint,
  and activated by local or compatible signed-policy opt-in. Actual applied
  credential receipts establish monitoring only for the current attachment epoch.
  Root namespace scope and restored saved-root credentials remain distinct; every
  new privilege rule is detection-only. Global exec/commit_creds workload and
  storage cost still require per-host measurement; fork-only ancestry fallback
  and direct kernel credential writes are outside this sensor proof.
- Phase 3 in-process code execution is design only. No runtime USDT/uprobe,
  language agent or compile/eval sensor is implemented by these observations.
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
- Managed RPM updates require a manually bootstrapped updater-capable package,
  signed enrollment-bound plan and short apply lease. The daemon reports its
  running build separately from installed RPM metadata. Interrupted applies
  reconcile without another RPM transaction; package rollback is not automatic.
- Process integrity and TPM attestation remain deferred. The deployed host stays
  in observe mode; SIGTERM is experimental, explicit opt-in and conservatively
  refuses unprovable process identity. It cannot prevent exec or guarantee exit.
- Project code is MIT; linked dependencies retain upstream license terms and
  notices included in source archives and RPMs. Tetragon remains external.
- The installer does not certify untested OS support or activate a collector
  solely because the API becomes ready.
