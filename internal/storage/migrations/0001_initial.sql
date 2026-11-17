CREATE TABLE events (
    event_id          TEXT PRIMARY KEY,
    schema_version    TEXT NOT NULL,
    host_id           TEXT NOT NULL DEFAULT '',
    boot_id           TEXT NOT NULL DEFAULT '',
    stream_id         TEXT NOT NULL DEFAULT '',
    sequence          INTEGER NOT NULL DEFAULT 0,
    event_time_ns     INTEGER NOT NULL,
    ingest_time_ns    INTEGER NOT NULL,
    event_type        TEXT NOT NULL,
    source            TEXT NOT NULL DEFAULT '',
    source_event_id   TEXT NOT NULL DEFAULT '',
    completeness      TEXT NOT NULL DEFAULT '',
    process_key       TEXT NOT NULL DEFAULT '',
    event_json        BLOB NOT NULL
);

CREATE INDEX events_event_time_idx
    ON events(event_time_ns DESC);
CREATE INDEX events_type_time_idx
    ON events(event_type, event_time_ns DESC);
CREATE INDEX events_process_time_idx
    ON events(process_key, event_time_ns DESC)
    WHERE process_key <> '';
CREATE UNIQUE INDEX events_stream_sequence_idx
    ON events(boot_id, stream_id, sequence)
    WHERE stream_id <> '' AND sequence > 0;

CREATE TABLE processes (
    process_key        TEXT PRIMARY KEY,
    parent_key         TEXT NOT NULL DEFAULT '',
    boot_id            TEXT NOT NULL DEFAULT '',
    exec_id            TEXT NOT NULL DEFAULT '',
    pid                INTEGER NOT NULL,
    ppid               INTEGER NOT NULL DEFAULT 0,
    start_time_ns      INTEGER NOT NULL DEFAULT 0,
    exe                TEXT NOT NULL DEFAULT '',
    origin_service     TEXT NOT NULL DEFAULT '',
    complete           INTEGER NOT NULL DEFAULT 0,
    first_seen_ns      INTEGER NOT NULL,
    last_seen_ns       INTEGER NOT NULL,
    exited_at_ns       INTEGER NOT NULL DEFAULT 0,
    process_json       BLOB NOT NULL
);

CREATE INDEX processes_pid_idx
    ON processes(boot_id, pid, start_time_ns DESC);
CREATE UNIQUE INDEX processes_identity_idx
    ON processes(boot_id, pid, start_time_ns)
    WHERE boot_id <> '' AND start_time_ns > 0;
CREATE INDEX processes_parent_idx
    ON processes(parent_key, start_time_ns);

CREATE TABLE findings (
    finding_id         TEXT PRIMARY KEY,
    rule_id            TEXT NOT NULL,
    rule_version       TEXT NOT NULL DEFAULT '',
    created_at_ns      INTEGER NOT NULL,
    severity           TEXT NOT NULL,
    confidence         REAL NOT NULL DEFAULT 0,
    state              TEXT NOT NULL,
    process_key        TEXT NOT NULL DEFAULT '',
    source             TEXT NOT NULL DEFAULT '',
    finding_json       BLOB NOT NULL
);

CREATE INDEX findings_created_idx
    ON findings(created_at_ns DESC);
CREATE INDEX findings_state_created_idx
    ON findings(state, created_at_ns DESC);
CREATE INDEX findings_process_idx
    ON findings(process_key, created_at_ns DESC)
    WHERE process_key <> '';

CREATE TABLE finding_events (
    finding_id TEXT NOT NULL REFERENCES findings(finding_id) ON DELETE CASCADE,
    event_id   TEXT NOT NULL REFERENCES events(event_id) ON DELETE RESTRICT,
    position   INTEGER NOT NULL,
    PRIMARY KEY (finding_id, event_id)
);

CREATE INDEX finding_events_event_idx ON finding_events(event_id);

CREATE TABLE capability_reports (
    report_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    observed_at_ns  INTEGER NOT NULL,
    report_json     BLOB NOT NULL
);

CREATE INDEX capability_reports_observed_idx
    ON capability_reports(observed_at_ns DESC, report_id DESC);

CREATE TABLE metadata (
    key        TEXT PRIMARY KEY,
    value      BLOB NOT NULL,
    updated_at_ns INTEGER NOT NULL
);
