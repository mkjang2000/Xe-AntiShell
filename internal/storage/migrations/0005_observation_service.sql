-- Only retained file and TCP events need a service lookup. Keep the lookup
-- separate so existing hosts can backfill by seeking the two event-type ranges.
CREATE TABLE observation_services (
    event_id TEXT PRIMARY KEY REFERENCES events(event_id) ON DELETE CASCADE,
    service TEXT NOT NULL,
    event_time_ns INTEGER NOT NULL
) WITHOUT ROWID;

INSERT INTO observation_services(event_id, service, event_time_ns)
SELECT event_id, COALESCE(NULLIF(json_extract(event_json,'$.process.origin_service'),''),'unknown'), event_time_ns
FROM events INDEXED BY events_type_time_idx
WHERE event_type IN ('file.write','network.connect');

CREATE INDEX observations_service_time_idx ON observation_services(service, event_time_ns DESC, event_id DESC);

CREATE TRIGGER record_observation_service AFTER INSERT ON events
WHEN NEW.event_type IN ('file.write','network.connect') BEGIN
    INSERT INTO observation_services(event_id, service, event_time_ns)
    VALUES (NEW.event_id, COALESCE(NULLIF(json_extract(NEW.event_json,'$.process.origin_service'),''),'unknown'), NEW.event_time_ns);
END;
