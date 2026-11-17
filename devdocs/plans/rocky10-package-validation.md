# Purpose

Prepare an EL10 x86_64 agent RPM and installation bundle for two Rocky Linux 10
test hosts (one VM and one physical AMD server).

# Scope

- Build the existing committed source in the Rocky Linux project's EL10 container
  userspace using the pinned Go module dependencies and static Go binaries.
- Use only a clean Git archive as container input. Do not mount host credentials,
  host configs, Docker socket, production databases or runtime directories.
- Keep build resources bounded; no privileged container, host network/PID mounts,
  kernel module access or changes to existing services.
- Inspect the resulting RPM, install it in disposable EL10 userspace and exercise
  binary startup, configuration loading, local API and replay detection.
- Produce RPM, installer, public central CA, checksums and operator instructions.
  Do not issue enrollment secrets before the target IDs and deployment are ready.

# Compatibility and limits

Both host types use the same x86_64 package. Actual event-source capabilities are
reported separately per host. A container shares the current host kernel, so this
work validates EL10 userspace/package behavior and does not certify Rocky 10
kernel tracing, SELinux policy, systemd service execution or VM/hardware behavior.
No live enforcement or network firewall changes are part of package preparation.
The selected central hostname also needs the separately identified server SAN,
non-loopback agent listener and firewall setup before remote enrollment.

# Validation

Check source privacy, immutable source revision, base image digest/OS version,
RPM architecture/release/requires/content, install scriptlets, installed binary
versions, package verification and isolated replay detection. Record validation
and limitations with the produced artifacts and leave production services intact.
