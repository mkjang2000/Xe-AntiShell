# MIT Licensing and Initial Publication

## Purpose and Authorization

Publish the reviewed source to the owner's repository at
`https://github.com/mkjang2000/Xe-AntiShell`. The owner chose MIT for project
code and confirmed that the destination is public on 2026-11-17. This supersedes
the earlier private-review and undecided-license assumptions.

## Scope and Design

- Add the project MIT license, repository URL and README license guidance.
- Preserve upstream licenses for statically linked Go dependencies, runtime and
  relevant bundled implementation notices. Include notices in source archives
  and the binary RPM; the project license does not relicense upstream code.
- Explain the external Tetragon boundary. This repository neither bundles its
  distribution nor ships custom eBPF programs. Upstream binary/eBPF licensing
  remains separate from the license on this agent's own implementation.
- Bump the RPM release for changed licensing metadata and payload. Do not
  install it or restart current services as part of source publication.
- Connect `origin`, create the initial commit and push `main` after source and
  package checks. Confirm remote emptiness first; never force-push or overwrite
  existing remote work. Do not change repository visibility.

## Validation and Failure Handling

Inspect Git candidates with local-only private patterns before staging and
check the final staged set for host records, secrets and generated artifacts.
Test the archive allowlist with required license fixtures so notices cannot
silently disappear. Export only the index and validate the shareable source,
static build and RPM license payload. Confirm the pushed commit matches the
remote branch and check CI results when available.

If remote authentication or push fails, retain the reviewed local commit and
report the specific blocker. Do not print tokens, credential configuration or
private deployment data while investigating.

## Local Validation before Publication

- Confirmed the destination is public, empty and writable by the authenticated
  owner. A separate remote-head check also found no existing branches.
- Checked 212 candidate source files with generic rules and local-only private
  patterns. Host configuration, deployment records, credentials and generated
  files are absent from the Git index.
- Exported the index without Git metadata; `make verify` passed, including the
  installer/build mocks, 16 hygiene regressions, Node-backed UI checks, Go vet,
  race tests and four static binaries.
- Built `0.1.0-14.el9.x86_64` from the shareable source with the offline module
  cache. RPM metadata and digests passed. Extracted the license payload and
  compared the project license, inventory and all 39 upstream text files to
  their source bytes; all matched. No active `/etc/audit` files are packaged.
- No package installation or live service changes were performed. Other OS
  targets and collector behavior retain the validation limits in README.
