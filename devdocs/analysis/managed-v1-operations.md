# Managed Agent Operations

The central service is maintained in the independent
[Xe-AntiShell-Central project](https://github.com/mkjang2000/Xe-AntiShell-Central).
Its [operations guide](https://github.com/mkjang2000/Xe-AntiShell-Central/blob/main/devdocs/analysis/managed-v1-operations.md)
owns server initialization, certificate SAN/listener setup, token issuance,
operator APIs, signed policy deployment and central backups. This agent
repository retains only its side of those procedures.

## Enrollment

Start the agent, obtain a trusted central CA certificate and an agent-scoped,
expiring enrollment credential through an authenticated channel, and run as
root:

```sh
sentinel managed enroll \
  --central https://central.example.internal:9443 \
  --agent-id HOST_ID \
  --ca-file /root/central-ca.crt \
  --token-file /root/xe-enrollment-token \
  --recovery-file /root/xe-offline-recovery
sentinel managed status
```

The token/recovery files must be owner-only. Keep the recovery file securely
outside this host. Existing enrollment and recovery state survive upgrades;
project/package separation requires no reenrollment or new CA.

## Policy and Delivery Checks

Check `enrolled`, `policy.desired_revision`, `policy.active_revision`,
`policy.result`, `last_contact_at`, `delivery.pending` and `delivery.lost_records`.
A revision is active only after local signature, target, expiry, rollback and
collector-coverage checks. A centrally committed ACK is required before local
outbox deletion; offline operation keeps local detection and bounded retries.

The shared contract is
[`protocol/managed`](https://github.com/mkjang2000/Xe-AntiShell/tree/protocol/v0.1.0/protocol/managed).
Defaults remain observe/none. Extended process rules are opt-in, require empty
executable filters and are independently excluded from automatic termination.

## Authorized Removal and Recovery

Use `sentinel managed challenge` to prepare a removal operation. Obtain an
operation/agent/enrollment-bound signed grant from the central operator, then
use `sentinel managed authorize-removal --operation OPERATION_ID --grant-file
PATH`. Normal authorization and the removal-start audit require central ACK.
For the offline emergency path use `sentinel managed recover-removal --operation
OPERATION_ID --code-file PATH`; the recovery verifier is one-use and locally
audited. Follow the complete central operations guide for grants and retention.

The agent RPM checks `sentinel managed removal-check` before final removal.
A fully privileged bypass can still prevent a last send; local audit retention
must not be described as guaranteed central delivery.

## Package Separation

The agent and central have independent RPMs and service hooks. See the
[separation and legacy migration plan](../plans/central-project-separation.md)
before upgrading an earlier combined package on a central host. Preserve
configuration, SQLite state, PKI and local unit overrides. Do not initialize
central state or reenroll existing agents during that transfer.
