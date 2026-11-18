-- Count committed event JSON by the UTC date of insertion. Replays and
-- retention do not change historical throughput. Pre-upgrade days are unknown.
CREATE TABLE daily_event_storage (
    utc_day TEXT PRIMARY KEY,
    stored_events INTEGER NOT NULL,
    stored_bytes INTEGER NOT NULL
) WITHOUT ROWID;
CREATE TRIGGER count_event_storage AFTER INSERT ON events BEGIN
    INSERT INTO daily_event_storage VALUES(date('now'), 1, length(NEW.event_json))
    ON CONFLICT(utc_day) DO UPDATE SET
        stored_events = stored_events + 1,
        stored_bytes = stored_bytes + excluded.stored_bytes;
END;

-- Initialize from durable rows exactly once, including audits queued before
-- enrollment. All later changes participate in the writer's own transaction.
CREATE TABLE outbox_usage (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    pending_records INTEGER NOT NULL CHECK(pending_records>=0),
    pending_bytes INTEGER NOT NULL CHECK(pending_bytes>=0)
);
INSERT INTO outbox_usage SELECT 1, count(*), coalesce(sum(length(payload)),0) FROM delivery_outbox;
CREATE TRIGGER count_outbox_insert AFTER INSERT ON delivery_outbox BEGIN
    UPDATE outbox_usage SET pending_records=pending_records+1, pending_bytes=pending_bytes+length(NEW.payload) WHERE singleton=1;
END;
CREATE TRIGGER count_outbox_delete AFTER DELETE ON delivery_outbox BEGIN
    UPDATE outbox_usage SET pending_records=pending_records-1, pending_bytes=pending_bytes-length(OLD.payload) WHERE singleton=1;
END;

ALTER TABLE delivery_checkpoint ADD COLUMN disconnect_at_ns INTEGER NOT NULL DEFAULT 0;
ALTER TABLE delivery_checkpoint ADD COLUMN first_recovery_ack_ns INTEGER NOT NULL DEFAULT 0;
ALTER TABLE delivery_checkpoint ADD COLUMN drained_at_ns INTEGER NOT NULL DEFAULT 0;
ALTER TABLE delivery_checkpoint ADD COLUMN losses_at_disconnect INTEGER NOT NULL DEFAULT 0;
ALTER TABLE delivery_checkpoint ADD COLUMN losses_at_drain INTEGER NOT NULL DEFAULT 0;
