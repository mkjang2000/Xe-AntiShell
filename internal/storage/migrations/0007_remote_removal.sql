CREATE TABLE remote_removal_operations (
    operation_id TEXT PRIMARY KEY REFERENCES removal_operations(operation_id),
    order_id TEXT NOT NULL UNIQUE,
    agent_id TEXT NOT NULL,
    enrollment_id TEXT NOT NULL,
    expires_at_ns INTEGER NOT NULL
);
