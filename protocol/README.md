# Xe-AntiShell Protocol

Shared, versioned contracts for the Xe-AntiShell agent and independent central
server. This Go 1.22 module uses only the standard library and is licensed under
the [MIT License](LICENSE).

```sh
go get github.com/mkjang2000/Xe-AntiShell/protocol@v0.1.1
```

- `model` contains collector-independent host, capability, process, event,
  finding and status definitions.
- `managed` contains bounded enrollment, heartbeat, delivery and policy wire
  types, Ed25519 policy/removal signing, and recovery-code verification.
- `managed.InstallationCode` carries a bound enrollment credential, central URL,
  expiry and public CA in one operator-delivered `xeas1.` value. Obtain it through
  an authenticated channel, protect it as a secret, and validate it before sending
  the enrollment credential. It is a transport envelope, not a signed policy.

The module contains no service, database, collector, response executor or host
configuration. Callers enforce transport limits and own durable delivery,
revision, authorization and single-use recovery/removal state.

## Compatibility

Version `v0.1.0` extracts the existing agent and central contracts without changing
field order, JSON/YAML tags, validation, signature domains or recovery digests.
The managed wire schema remains `1`; the core event schema remains `0.1`.

Version `v0.1.1` adds installation-code helpers and strict enrollment-origin
validation. Existing enrollment responses, signed policies, removal grants and
recovery verification digests are unchanged.

Signing marshals the typed payload with `encoding/json`, including declaration
order and nil-versus-empty collection behavior. Preserve these bytes when
changing signed types. In particular, a false `extended_process_rules` is omitted
so policies issued before that option remain verifiable. Enabling the option is
covered by the signature. Fixed-key policy and removal JSON fixtures were
captured before extraction and protect compatibility alongside legacy-policy,
domain-separation, replay and target-scope regression tests. The fixture keys are
public, deterministic test data only.

A signed detection policy can carry `service_observations`. Omitting this field
inherits the host's configured scopes. An explicit empty array clears all
scopes. A populated array replaces them for services selected by the policy.
A CIDR with omitted or empty ports allows every port on that prefix. An empty
destination list disables that service's TCP destination rule. Publishers must
check support on each target before sending the field, including an empty list.
Legacy agents strictly decode their supported schema. The entire signed policy
envelope, including the signature and key identifier, fits within 64 KiB.

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
