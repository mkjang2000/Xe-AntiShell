# Purpose and completion criteria

Manage agent RPM versions centrally and deploy an approved release to selected
servers or groups. Report actual installed RPM and running build separately.
Retain the detection-first observation configuration, enrollment and policies.
Existing agents require one manual bootstrap upgrade to install the updater.

RPM epoch/version/release comparison and component syntax follow the
[official RPM version specification](https://rpm.org/docs/6.0.x/man/rpm-version.7).
Epoch is retained in package and running-build identities; prerelease operators
are accepted as metadata rather than interpreted as command text.

# Architecture and interfaces

The shared `managed` protocol adds domain-separated signed update plans and
short install authorizations using the already pinned policy public key. Plans
bind agent/enrollment, independent monotonic revision, exact expected installed
RPM, immutable release SHA-256/size/platform and expiry. No commands, shell
arguments or remote URLs are accepted. A fresh install authorization binds the
canonical plan digest after download and checks that the central job is still
current. Heartbeat and policy JSON remain unchanged; inventory and update reports
use separate APIs, preserving compatibility with older strict central decoders.

Agent APIs: POST `/v1/update/status`, GET `/v1/update`, GET
`/v1/update/artifacts/{sha256}`, POST `/v1/update/claim`, POST
`/v1/update/report`. All use existing enrollment mTLS. JSON has bounded strict
decoding. Artifacts have a separate 64 MiB, five-minute streaming boundary,
same-origin construction, no redirects and no proxy-dependent trust changes.

Central console: release list/upload/delete, inventory, target preview,
rollout creation/list/detail and cancellation of jobs not yet installing. Release
upload/delete require admin; operators can deploy approved releases. Viewers
can inspect. Every mutation retains CSRF and role checks. RPM installation
scripts execute as root: approving a release grants that code-deployment trust.
Fixed metadata checks are not a substitute for trusting the uploaded package.

# Data and process flow

Admin upload -> bounded RPM metadata inspection -> immutable SHA blob and release
metadata -> enrollment/package/group snapshot preview -> confirmed rollout ->
sequential dispatch -> agent inventory/plan verification -> bounded download ->
fresh install claim -> root-only immutable local job -> independent systemd
updater -> signature/identity/expiry/hash/metadata recheck -> fixed RPM test/install
-> daemon restart and observed build/health -> durable result -> central report.

The daemon has a read-only system filesystem and cannot safely replace itself.
A separate, thin updater entry point owns package installation. It checks the
current package again, never uses downgrade/force/replace options, and holds an
exclusive lock. Local remote-updates setting defaults enabled for enrolled RPM
agents, with an explicit opt-out. Source/dev, missing helper/unit, unsupported
platforms and custom unsupported paths report unavailable without installation.

New central tables are additive and leave the previous database version and
existing tables compatible. Inventory, releases, previews, rollout jobs, per-
enrollment heads and monotonic exact-retry reports are distinct responsibilities.
Mixed-target previews show exclusions and create jobs only for the explicitly
confirmed eligible subset. Group membership, enrollment and current package are
rechecked before creating jobs. Default dispatch is sequential and stops the
remaining unstarted targets after the first failed, expired or unknown outcome.
Queued/offered jobs expire; an install lease already handed to an updater cannot
be safely revoked by a UI cancellation.

# Failures and limits

Reject expired, replayed, foreign-enrollment, tampered, incompatible or stale
precondition jobs before installation. Never overwrite an unrelated local file
or trust symlinked/writable spool paths. Persist phases and sequence before
reporting. A daemon restart resumes reporting, not an unconditional RPM rerun.
Interrupted installations are reconciled against actual package/build state;
unknown or failed transactions remain visible and require a new operator job.
Bounded late reports are acknowledged as history after a server-side terminal
outcome; they do not revive a job, alter a newer head or resume a stopped rollout.
Existing journal reconciliation/reporting continues even if a host has disabled
new remote installations. Re-enrollment invalidates old jobs and does not transfer
the old revision floor or signing identity into the new enrollment.
Do not promise automatic downgrade, database restore or power-loss atomicity.
RPM transaction triggers can also consume pending systemd restart markers from
other package transactions; a package update is not isolated from the host's
package-manager lifecycle. Do not clear unrelated markers or package locks.

Keep reports to fixed codes and bounded package/build metadata. Do not transmit
RPM stderr, argv, environments, credentials or arbitrary command output. Control
artifact count/disk quota and protect active job references from deletion.

# Independent release origin and build signing

The publisher signs artifact name, package/platform, SHA-256, size and publication
time with a separate Ed25519 key. Its public anchors are built into central and
the agent; remote policy or upload fields cannot add keys. Central validates the
publisher before reading a large manual RPM body or downloading a GitHub RPM,
then checks actual bytes/header. The daemon and privileged updater independently
verify it again. Central's per-host approval key cannot sign a trusted release.
The update wire protocol is version 2; heartbeat/policy formats remain unchanged.

The owner approved this as a combined development/build and central host. The
publisher private key is outside Git, central state and RPM payloads in a
root-only build directory that the central account cannot read. This is permission
separation on one host, not physical separation. The developer signing CLI and
local publication script can later move to another host. Initial GitHub Actions
jobs build unsigned artifacts only; uploading a private key to CI is neither
automatic nor required.

Manual upload requires the RPM plus its signed public manifest. GitHub import
uses the fixed project repository, bounded HTTPS/public-address destinations,
redirect limits and the same verified catalog path. No raw URL is accepted.
Post-update checks compare actual installed RPM and live daemon build, then
verify fresh execution receipt when the previous collector was running. An
unavailable/disabled pre-existing collector is explicitly not applicable; a lost
active stream is a failed collection check, not a successful package deployment.

# Validation

Protocol signature/domain/target/revision/lease/bounds tests; client mTLS,
redirect/timeout/oversize/hash tests; updater root-file ownership/symlink/locking,
duplicate/interruption/precondition tests with substituted command execution;
central upload/RBAC/CSRF/quota, snapshot/idempotence/concurrency/cancellation tests;
light/dark/mobile UI and keyboard/accessibility checks. Build RPMs and exercise
actual package changes only in isolated containers before a backed-up local
bootstrap and a concrete central deployment test. Keep EL10 userspace validation
separate from kernel/boot claims. Update structural maps as modules are added.
