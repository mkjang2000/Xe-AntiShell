# Xe-AntiShell Protocol

Shared, versioned contracts for the Xe-AntiShell agent and independent central
server. This Go 1.22 module uses only the standard library and is licensed under
the [MIT License](LICENSE).

```sh
go get github.com/mkjang2000/Xe-AntiShell/protocol@v0.1.0
```

- `model` contains collector-independent host, capability, process, event,
  finding and status definitions.
- `managed` contains bounded enrollment, heartbeat, delivery and policy wire
  types, Ed25519 policy/removal signing, and recovery-code verification.

The module contains no service, database, collector, response executor or host
configuration. Callers enforce transport limits and own durable delivery,
revision, authorization and single-use recovery/removal state.

## Compatibility

Version `v0.1.0` extracts the existing agent and central contracts without changing
field order, JSON/YAML tags, validation, signature domains or recovery digests.
The managed wire schema remains `1`; the core event schema remains `0.1`.

Signing marshals the typed payload with `encoding/json`, including declaration
order and nil-versus-empty collection behavior. Preserve these bytes when
changing signed types. In particular, a false `extended_process_rules` is omitted
so policies issued before that option remain verifiable. Enabling the option is
covered by the signature. Fixed-key policy and removal JSON fixtures were
captured before extraction and protect compatibility alongside legacy-policy,
domain-separation, replay and target-scope regression tests. The fixture keys are
public, deterministic test data only.

The agent keeps aliases for these core definitions in its internal model package;
agent-local history and operator UI models remain outside this module. Both
projects pin a published module version. Repository releases use
`protocol/vX.Y.Z` tags; release `go.mod` files do not need a local `replace`.

## Validation

Run from this directory:

```sh
GOWORK=off go test ./...
GOWORK=off go vet ./...
GOWORK=off go test -race ./...
```
