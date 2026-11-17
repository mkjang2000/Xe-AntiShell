# Scope

Investigate a host-specific failure of
`TestSamplerNeverOpensProcessArgumentsOrEnvironment` during the observation
feature's full race validation. No sampler or privacy assertion was changed.

# Findings

The test puts inotify open/access watches on synthetic `cmdline` and `environ`
files under a private temporary fixture. The sampler only reads the documented
counter/status/cgroup files and resolves the executable link. Its source has no
read path to either sensitive fixture file.

The focused test also failed consistently when executed outside the restricted
validation environment, so the failure was not specific to parallel package tests.
An independent reproduction created and watched the same synthetic file names
without invoking the sampler. It still received `IN_OPEN` from the surrounding
host environment. The corresponding restricted run received no events. These
global inode notifications do not establish that the sampler opened the file.
No production process arguments, environments or event bodies were read or
printed during this investigation.

# Validation Method

Retain the test unchanged and execute the full hostmetrics package inside the
restricted environment, including three independent race-test repetitions:

```sh
GOWORK=off GOCACHE=/tmp/xeas-agent-gocache \
  go test -race ./internal/hostmetrics -count=3
```

Run every other package's race tests in the environment that permits their
localhost listeners. This partitions execution by environmental requirement;
it does not skip a package, remove a privacy assertion or suppress a failure.
Source/script/UI checks, vet, static builds and replay verification remain
separate required checks. Do not report a single unrestricted full-suite run
as passing when this host interference occurred.

# Limits

This is evidence of environment interference with a global file watch, not a
claim that unrelated host readers are safe or that privacy checks may be ignored.
Further host-reader tracing and host configuration changes are outside this
development task. The public package and its runtime behavior are unaffected.
