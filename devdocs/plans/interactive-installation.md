# Purpose

Keep scripted installation compatible and add a Korean step-by-step wizard when
install.sh runs without arguments on a terminal. Central enrollment should need
one pasted installation token rather than manually moving CA and recovery files.

# Design

1. Shared managed.InstallationCode encodes a versioned, bounded `xeas1.` token
   containing central HTTPS origin, bound agent ID, expiry, single-use secret and
   the central public CA PEM. It is obtained through the authenticated central
   console. This trusted operator delivery carries the CA before any network
   credential is sent; no unverified TLS connection or TOFU is introduced.
2. Add `sentinel managed enroll-code --code-file PATH [--recovery-file PATH]`.
   Decode/validate the installation code, then reuse existing enrollment and
   durable recovery preparation. Client private keys stay agent-generated; the
   existing central enrollment response delivers the signed client certificate.
   Recovery plaintext is generated/stored on the agent only and must be backed
   up off-host; central never stores or transmits that recovery plaintext.
3. Add `install.sh --enrollment-file PATH` for automation (optional defaulted
   recovery path), mutually exclusive with the legacy five enrollment options.
   Existing `--rpm`, `--build`, `--enable-web`, and complete legacy options retain
   their behavior. Unknown/mixed/incomplete options fail before package changes.
4. No-argument TTY flow: detect OS/architecture → choose matching local RPM/manual
   RPM/build → choose central or standalone → hidden installation-token paste
   (if central) → optional local panel → non-secret summary and final confirm.
   Secrets use private temporary files, are never command arguments/environment
   values/log output, and are removed on cancel/error/signal. Piped input without
   arguments fails clearly. Recovery defaults to a root-only durable file.
5. Central adds explicit `--enrollment-url HTTPS_ORIGIN`; verify the loaded server
   certificate covers that name. Token issuance retains its raw-token response
   for legacy clients and adds installation_code when the URL is configured.
   The web console defaults to showing/downloading the complete installation code
   and explains that it can be pasted into the wizard. State exposes readiness
   and the public enrollment URL; secrets are returned only at issuance.

# Scope

Agent installer/CLI/client helpers, shared protocol additive release v0.1.1,
central issue/CLI/console UI, source archive selectors if needed, documentation,
RPMs and Rocky10 installation bundle. Existing signed-policy/ACK/enrollment/removal
wire schemas and immutable compatibility fixtures stay unchanged.

# Failure cases

Reject malformed/oversized/expired codes, conflicting enrollment modes, bad CA
or URL, redirected/incorrect-host TLS, mismatched IDs and reused credentials for
different identities. Preserve existing config/credentials/recovery on retries;
network failure must not erase the recovery code or pending CSR. Do not print
input code in parse errors. Installation success remains distinct from verified
runtime collection. No auto-enforcement. Optional Tetragon setup is an explicit
choice described in [the collector installation plan](tetragon-installation.md).

# Validation

Protocol roundtrip/privacy/boundary tests; CLI wrong trust/expired input/retries;
installer command mocks and PTY wizard tests (central/standalone/cancel/non-TTY,
secret suppression, optional panel, old flags); central issuance/CA/expiry/secret
privacy and browser copy/download; full Go/JS/source/script checks and independent
multi-agent enrollment. Build/install/replay smoke in Rocky10 userspace, followed
by live central rollout preserving all existing identities and observe policies.

# Signal cleanup follow-up

The script entry keeps the calling Bash alive while the `main` subshell finishes
EXIT cleanup. A process-group termination must not return control to the caller
before terminal restoration and secret-file cleanup finish. PTY regression tests
delay the restoring `stty` and require complete restoration plus exact INT/TERM/
HUP exit statuses. Existing caller traps and umask remain scoped correctly.

Two preexisting input/supervision limits remain separate: a signal sent only to
the outer PID is not forwarded to the inner installer, and rare SIGINT timing
can leave Bash's character read waiting under repeated stress. The group-cleanup
correction does not claim to resolve those cases or change secret-input parsing.
