CREATE TABLE managed_state (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    state_json BLOB NOT NULL
);
CREATE TABLE pending_enrollment (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    state_json BLOB NOT NULL
);
CREATE TABLE delivery_outbox (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    record_id TEXT NOT NULL,
    payload BLOB NOT NULL,
    created_at_ns INTEGER NOT NULL,
    UNIQUE(kind,record_id)
);
CREATE TABLE delivery_checkpoint (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    spool_id TEXT NOT NULL,
    acknowledged INTEGER NOT NULL DEFAULT 0,
    lost_records INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE managed_policy (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    revision INTEGER NOT NULL,
    signed_json BLOB NOT NULL,
    applied_at_ns INTEGER NOT NULL
);
CREATE TABLE removal_operations (
    operation_id TEXT PRIMARY KEY,
    challenge TEXT NOT NULL UNIQUE,
    mode TEXT NOT NULL DEFAULT '',
    authorization_id TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL,
    audit_sequence INTEGER NOT NULL DEFAULT 0,
    created_at_ns INTEGER NOT NULL,
    authorized_at_ns INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE consumed_authorizations (
    authorization_id TEXT PRIMARY KEY,
    operation_id TEXT NOT NULL,
    consumed_at_ns INTEGER NOT NULL
);
CREATE TABLE response_claims (
    finding_id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL,
    created_at_ns INTEGER NOT NULL
);
