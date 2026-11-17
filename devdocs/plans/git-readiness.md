# Installation and Repository Readiness

This records the initial private preparation. The later owner-authorized public
repository and MIT decision are covered in [MIT publication](mit-publication.md).

## Purpose

Prepare a reviewable initial source repository and a repeatable installation
path. Preserve the current running host; this task does not require reinstalling
services or publishing to an unknown remote. The existing local-RPM installer
will gain a source-build path instead of being duplicated.

## Scope

- Keep `--rpm` compatible and add mutually exclusive `--build` using a safe RPM
  builder. Perform option/credential/web prerequisites before host mutations.
- Preserve configuration, initial-login delivery files and offline recovery
  credentials across retries. No automatic enforcement/firewall/audit changes.
- Package audit rules/plugins as inert templates under the application share
  directory. Previous packages placed them in auditd's active directories;
  upgrading such deployments needs explicit rule/plugin migration and effective
  state verification. Do not let a fresh install activate global exec capture
  merely through a later auditd restart.
- Separate deployment-specific host configuration and live validation notes from
  shared source. Preserve private originals locally, provide generic examples.
- Add repository ignores/attributes, source hygiene checks, repeatable build and
  test commands, and CI. Include source tests/fixtures but exclude generated
  binaries, databases, PKI/auth/recovery files, credentials and tool state.
- Review license/publishing intent before assigning a public license. Remove
  placeholder project URLs rather than inventing an owner or remote.
- Initialize a local Git repository and review the staged candidate set if the
  environment allows it. Remote creation, pushing and public release remain
  separate actions requiring an actual destination.

## Verification

Installer command mocks cover validation-before-mutation, build mode, paths with
spaces, repeat installation, enrollment retry and credential preservation. Build
tests cover output safety and source exclusions. Source checks inspect candidate
text without displaying credential values, reject runtime/private artifacts,
check documentation links and verify ignores. Run gofmt/vet/race, Node-backed UI
tests, shell/build checks and a real static RPM build from the shareable source.
Check resulting archive/package contents and ensure current service state is
unaffected. Update README and Project_tree with concrete commands and limits.

## Validation Results

- Reviewed 170 Git candidate files with the generic rules and local-only host
  patterns: no findings. Private host configuration, deployment notes and local
  credential/tool paths remain ignored. No remote or public license is selected.
- Exported only the Git index into a temporary directory without Git metadata.
  `make verify` passed there: source/format/shell/JavaScript checks, 16 source
  hygiene regressions, installer/build mocks, Go vet/race tests and four static
  binaries. Node was present, so browser-module tests were not silently skipped.
- Built a real `0.1.0-13.el9.x86_64` RPM from that shareable source with Go 1.22
  and the offline module cache. Package metadata/digests passed; all four
  binaries are static ELF. Audit templates are present under the application
  share directory, with no files under `/etc/audit`.
- Host installation, reboot, upgrade from earlier packages, live collector
  changes and remote GitHub Actions were not exercised in this task. Existing
  services were not changed. Other OS targets, including CentOS 7's older RPM
  payload support and web-unit compatibility, still need VM validation.
