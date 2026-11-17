# Purpose

Extend the existing installer with optional, verified Tetragon setup and a
collector-only path for already installed agents. Registration alone must not be
reported as working process observation.

# Current Structure

`install.sh` orchestrates RPM installation, enrollment and the local web panel.
`packaging/install-wizard.sh` supplies terminal prompts. The Go agent already
accepts Tetragon JSON through a configured `tetra getevents` child process. Its
collector counters and runtime capabilities distinguish process startup from
actual exec evidence. Third-party Tetragon is not part of the agent RPM.

# Requirements and Interfaces

- `./install.sh` offers a Tetragon step, default yes, with download/dependency
  disclosure before the final confirmation. Scripted installations retain their
  old defaults and opt in using `--with-tetragon`.
- `sudo ./install.sh --tetragon-only` configures an installed agent without an
  RPM transaction or reenrollment. Optional `--tetragon-archive PATH` supplies
  the same verified artifact offline and requires a Tetragon setup mode.
- A small Bash bridge checks prerequisites and installs Python3/PyYAML through
  dnf only when necessary. A modular Python helper owns artifact verification,
  preserved YAML updates, service lifecycle, verification and rollback.
- First automated artifact: official Tetragon v1.8.0 Linux amd64, SHA256
  `e88691c5f05a2a61aba58974a080603050b924c7f13ecc06f3d05172feb05f59`.
  Install selected verified binaries/BPF objects under a versioned project
  directory. Never execute the upstream install script, which starts the daemon
  before project overrides can be applied.

# Data Flow and Boundaries

Explicit selection → prerequisites → verified private artifact staging →
preserved config backup → root-only Unix Tetragon service → health and benign
exec proof → collector-only YAML update → agent restart → fresh agent collection
evidence → success.

Keep credential state, database paths, privacy, response opt-in, detection rules
and existing filter settings. No change to central policy contracts or agent
enrollment. No tracing/enforcement policy is added. Empty policy directories and
critical CLI flags override upstream defaults; unrelated Tetragon installations
and custom agent unit/config paths require manual integration.

# Failure Handling and Compatibility

- Reject unsupported architecture or missing BTF explicitly. The first automated
  path targets Rocky/RHEL/Alma 8–10 prerequisites; kernel load/attach is still
  verified at runtime. CentOS7 audit fallback remains separate.
- Bound archive download/expanded sizes; reject wrong hashes, unsafe member
  paths, links, special files and duplicates before publishing executable files.
- Preserve the prior agent config and service state. A health, exec or agent
  verification failure restores the original collector and owned service state.
  Do not claim collection success based on process presence or an HTTP endpoint.
- `tetra status` is a gRPC client operation; initializing can return exit0.
  Event streams use stdin `/dev/null`, bounded reads and explicit deadlines.
- Do not disable SELinux, alter firewall rules or restart unrelated services.
- Do not print or persist captured process argv/environment. Keep backups
  owner-only and private, and never read enrollment credentials for setup.

# Validation Plan

Run installer command-mock and PTY privacy/cancel checks. Test pinned hash and
archive traversal rejection, config value preservation, readiness/exec gates,
rollback and idempotent retries using temporary roots and mocked commands. Run
the existing full project verification and Rocky10 userspace/package checks.
Actual remote Rocky10 kernel attach/SELinux validation remains an operator-side
check; do not change the running validation host's healthy collector to test it.

# Upstream References

- https://tetragon.io/docs/installation/package/
- https://github.com/cilium/tetragon/releases/tag/v1.8.0
- https://github.com/cilium/tetragon/blob/v1.8.0/cmd/tetra/status/status.go
- https://github.com/cilium/tetragon/blob/v1.8.0/cmd/tetra/getevents/getevents.go
