# Purpose

Keep configured collector discovery and operator presentation consistent with
actual process collection, including a versioned Tetragon installation outside
the service PATH.

# Cause and Scope

The agent's passive probe searched only `tetragon`/`tetra` in PATH while the
collector launched an explicit absolute command from configuration. Consequently
`collector.tetragon` could have passive `unsupported` and runtime `active` at the
same time. The central console returned "unsupported" before inspecting active
runtime evidence. The process exec/lineage rows could therefore disagree with
the collector row while the incoming stream was healthy.

# Design

- Pass the configured Tetra command to the default agent Prober. An explicit
  command is authoritative: finding another executable in PATH must not hide a
  missing or nonexecutable configured command. Keep legacy PATH discovery when
  the Prober has no explicit command.
- Passive executable/kernel/BTF discovery remains `limited`, never runtime
  `active`. Preserve the existing live-exec overlay and shared protocol.
- The central console uses fresh runtime evidence for the actual-operation
  column. Planned features, stale reports and explicit runtime errors keep their
  existing guards. Keep passive diagnostics visible as separate evidence and
  explain disagreement in Korean rather than suppressing either source.
- An active process eBPF report confirms process hooks only; it is not a claim
  that unrelated file/network/integrity collectors are implemented.
- Existing agents need no reinstall for the central presentation correction.
  New agent builds include the configured-path probe correction.

# Failure Cases and Validation

Test a working versioned command outside PATH, missing/nonexecutable explicit
commands despite an unrelated PATH executable, missing kernel/BTF prerequisites
and default constructor wiring. Verify no probe executes external binaries.
Test central unsupported/error passive reports with active runtime, stale and
planned reports, actual runtime errors and guarded termination semantics. Run
both projects' verification and package builds before updating the central
service. Preserve central PKI, accounts, enrollment, policy state and local
port/proxy overrides through a stopped-state backup and rollback procedure.
