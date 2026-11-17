# Central Project and Deployment Separation

## Purpose and Completion Criteria

Prepare independent agent and central projects for a multi-server pilot. Keep
the current observation deployment, registration, CA, policy keys, databases and
approved policy intact. Agent core detection and transport are pilot-ready;
production blocking, all-target OS validation and central UI remain unfinished.

## Current Structure

One Go module and RPM contain the agent, local monitoring panel and central
service. The RPM creates both service accounts and restarts all three binaries.
The central code imports only shared managed protocol and core model packages;
there is no need to share collector, local storage or detection implementation.

## Design

- Keep `Xe-AntiShell` as the agent/local-panel repository. Extract central into
  `Xe-AntiShell-Central`, a separate Go module, folder and public MIT repository.
- Keep shared contracts in a small `protocol/` Go submodule within the existing
  repository, published with `protocol/v0.1.0` tags. Both projects pin its release;
  do not create a third service or duplicate canonical policy definitions.
- Move managed protocol/crypto and core event/model definitions without changing
  JSON tags, field order, signature domains, policy schema or persisted shapes.
  Agent-local model aliases preserve internal imports while the shared package
  is the only definition. Keep local history/UI models in the agent.
- Use a temporary Go workspace for pre-publication validation only. Release
  go.mod files must work with the published version and no sibling-folder replace.
- Separate binaries, RPM ownership, users, units, installers, CI and test suites.
  The agent RPM must not install or restart central; central must not depend on
  the agent RPM or enforce the agent's uninstall policy.
- New central RPM retains `/usr/sbin/sentinel-central`, its unit/user and
  `/var/lib/xe-antishell-central` paths. Do not reinitialize PKI or reenroll.
  Transfer legacy bundled file ownership with a coordinated RPM transaction,
  backed up and verified before touching the current deployment.
- Preserve previous detection work in a local checkpoint before extraction.
  Work on a temporary central source tree inside the writable sandbox, then
  place the reviewed project at `/root/dev/Xe-AntiShell-Central`.

## Failure Handling and Compatibility

Never delete current databases, credentials or policy state to solve migration
errors. Retain the monolithic package as a rollback artifact. Package/file-owner
checks must establish a safe transfer order, and an agent-only installer should
detect a legacy local central deployment rather than silently removing it.
Keep ports, local systemd overrides and observe/none unchanged. Do not expose
listeners/firewall ports automatically or claim remote multi-host testing has
occurred before additional test hosts are supplied.

## Validation Plan

Run shared protocol signature/replay compatibility tests; independent agent and
central vet/race/build/source checks; isolated agent replay; enrollment, policy,
delivery and offline recovery contract integration. Build both RPMs from clean
source without the other project's tree. Inspect payloads and scriptlets, test
legacy ownership transfer in an isolated RPM database, then migrate the live
same-host installation with protected backups and independent-service checks.
Publish the shared module and both projects, confirm pinned dependency builds
and CI, and document the multi-server enrollment flow and remaining limits.

## Results

- Published the stdlib-only shared module as `protocol/v0.1.0`; agent and
  central require its public version and verified go.sum. Legacy/extended policy
  and removal signature golden fixtures match the pre-extraction implementation.
- Created the independent public central repository and the project folder
  `/root/dev/Xe-AntiShell-Central`, with its own installer, RPM, CI and guide.
  Central implementation differs only in imports; runtime paths are unchanged.
- Agent and central independent verification passed without a development
  workspace or sibling-folder replace. Agent replay still passes 16 cases.
  Built agent `0.1.0-16.el9` and central `0.1.0-1.el9` RPMs independently.
- The cross-project race test passed with the separate central executable and
  two isolated agent services. It checks per-agent policy/history isolation,
  heartbeat, local detection during interruption, queued replay and deduplication.
  This is not a claim of testing two different machines or kernel families.
- An isolated RPM database confirmed legacy binary/unit ownership transfer in
  one transaction. Its metadata-only check disabled payload/scripts/plugins and
  ignored disk-size accounting; the real host transaction used normal dependency,
  payload and scriptlet checks without those bypass flags.
- Migrated the existing same-host observation deployment to the separate RPMs
  after protected backups. Existing registration, policy revision 2, credentials,
  PKI, overrides and agent configuration survived. All services recovered healthy
  with zero loss. Restored central's enabled state after its first-package preset.
- Reinstalled only the new agent package and confirmed the central PID did not
  change. The agent payload and service hooks contain no central ownership.
