package storage

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"xe-antishell/internal/model"
)

// EventFilter bounds a newest-first event query. Zero-valued fields are not
// applied. Limit defaults to 100 and is capped to protect the local API.
type EventFilter struct {
	Type       string
	Source     string
	ProcessKey string
	After      time.Time
	Before     time.Time
	Limit      int
}

// SaveEvent durably inserts an immutable normalized event. Replaying an
// identical event ID is idempotent; reusing it for different content returns
// ErrConflict.
func (s *Store) SaveEvent(ctx context.Context, event model.Event) error {
	_, err := s.SaveEventResult(ctx, event)
	return err
}

// SaveEventResult is SaveEvent with an inserted result. A retry of the same
// stable source event returns inserted=false; reuse of an ID for different
// source content returns ErrConflict.
func (s *Store) SaveEventResult(ctx context.Context, event model.Event) (bool, error) {
	if event.ID == "" {
		return false, errors.New("storage: event ID is required")
	}
	if event.SchemaVersion == "" {
		return false, errors.New("storage: event schema version is required")
	}
	if event.Type == "" {
		return false, errors.New("storage: event type is required")
	}
	if event.EventTime.IsZero() || event.IngestTime.IsZero() {
		return false, errors.New("storage: event and ingest times are required")
	}
	if event.Sequence > math.MaxInt64 {
		return false, errors.New("storage: event sequence exceeds SQLite integer range")
	}

	body, err := json.Marshal(event)
	if err != nil {
		return false, fmt.Errorf("storage: encode event %q: %w", event.ID, err)
	}
	result, err := s.executor().ExecContext(ctx, `
INSERT INTO events(
    event_id, schema_version, host_id, boot_id, stream_id, sequence,
    event_time_ns, ingest_time_ns, event_type, source, source_event_id,
    completeness, process_key, event_json
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(event_id) DO NOTHING`,
		event.ID, event.SchemaVersion, event.HostID, event.BootID, event.StreamID,
		int64(event.Sequence), event.EventTime.UnixNano(), event.IngestTime.UnixNano(),
		event.Type, event.Source, event.SourceEventID, string(event.Completeness),
		event.Process.Key, body,
	)
	if err != nil {
		return false, fmt.Errorf("storage: insert event %q: %w", event.ID, err)
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("storage: inspect event insert %q: %w", event.ID, err)
	}
	if inserted == 1 {
		if err := s.recordSequence(ctx, event); err != nil {
			return false, err
		}
		return true, nil
	}

	var existing []byte
	if err := s.executor().QueryRowContext(ctx, `SELECT event_json FROM events WHERE event_id = ?`, event.ID).Scan(&existing); err != nil {
		return false, fmt.Errorf("storage: read duplicate event %q: %w", event.ID, err)
	}
	if bytes.Equal(existing, body) {
		return false, nil
	}
	existingEvent, decodeErr := decodeEvent(existing)
	if decodeErr == nil && sameSourceEvent(existingEvent, event) {
		return false, nil
	}
	return false, fmt.Errorf("%w: event ID %q", ErrConflict, event.ID)
}

func sameSourceEvent(left, right model.Event) bool {
	if left.SourceEventID == "" || left.SourceEventID != right.SourceEventID {
		return false
	}
	left.Sequence, right.Sequence = 0, 0
	left.IngestTime, right.IngestTime = time.Time{}, time.Time{}
	left.Process.FirstSeen, right.Process.FirstSeen = time.Time{}, time.Time{}
	left.Process.LastSeen, right.Process.LastSeen = time.Time{}, time.Time{}
	// Ancestor observation bounds are local too. Copy the slices before
	// clearing them so value comparison never rewrites caller-owned evidence.
	left.Ancestors = append([]model.Process(nil), left.Ancestors...)
	right.Ancestors = append([]model.Process(nil), right.Ancestors...)
	for index := range left.Ancestors {
		left.Ancestors[index].FirstSeen, left.Ancestors[index].LastSeen = time.Time{}, time.Time{}
	}
	for index := range right.Ancestors {
		right.Ancestors[index].FirstSeen, right.Ancestors[index].LastSeen = time.Time{}, time.Time{}
	}
	if isContextObservation(left.Type) && left.Type == right.Type {
		// IO/argument-match events carry context, never source lifecycle changes.
		// A later parent or exit must not turn a retry into different evidence.
		clearDerivedContext(&left.Process)
		clearDerivedContext(&right.Process)
		for index := range left.Ancestors {
			clearDerivedContext(&left.Ancestors[index])
		}
		for index := range right.Ancestors {
			clearDerivedContext(&right.Ancestors[index])
		}
	}
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}

// GetEvent returns an event by its immutable ID.
func (s *Store) GetEvent(ctx context.Context, eventID string) (model.Event, error) {
	var body []byte
	err := s.db.QueryRowContext(ctx, `SELECT event_json FROM events WHERE event_id = ?`, eventID).Scan(&body)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Event{}, fmt.Errorf("%w: event %q", ErrNotFound, eventID)
	}
	if err != nil {
		return model.Event{}, fmt.Errorf("storage: get event %q: %w", eventID, err)
	}
	return decodeEvent(body)
}

// ListEvents returns matching events newest first.
func (s *Store) ListEvents(ctx context.Context, filter EventFilter) ([]model.Event, error) {
	limit, err := boundedLimit(filter.Limit)
	if err != nil {
		return nil, err
	}

	var query strings.Builder
	query.WriteString(`SELECT event_json FROM events WHERE 1 = 1`)
	args := make([]any, 0, 6)
	if filter.Type != "" {
		query.WriteString(` AND event_type = ?`)
		args = append(args, filter.Type)
	}
	if filter.Source != "" {
		query.WriteString(` AND source = ?`)
		args = append(args, filter.Source)
	}
	if filter.ProcessKey != "" {
		query.WriteString(` AND process_key = ?`)
		args = append(args, filter.ProcessKey)
	}
	if !filter.After.IsZero() {
		query.WriteString(` AND event_time_ns >= ?`)
		args = append(args, filter.After.UnixNano())
	}
	if !filter.Before.IsZero() {
		query.WriteString(` AND event_time_ns < ?`)
		args = append(args, filter.Before.UnixNano())
	}
	query.WriteString(` ORDER BY event_time_ns DESC, event_id DESC LIMIT ?`)
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, query.String(), args...)
	if err != nil {
		return nil, fmt.Errorf("storage: list events: %w", err)
	}
	defer rows.Close()

	events := make([]model.Event, 0)
	for rows.Next() {
		var body []byte
		if err := rows.Scan(&body); err != nil {
			return nil, fmt.Errorf("storage: scan event: %w", err)
		}
		event, err := decodeEvent(body)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("storage: iterate events: %w", err)
	}
	return events, nil
}

// LastSequence returns the highest durable sequence for one boot-scoped
// stream. The agent uses it to avoid reusing sequence numbers after restart.
func (s *Store) LastSequence(ctx context.Context, bootID, streamID string) (uint64, error) {
	if bootID == "" || streamID == "" {
		return 0, errors.New("storage: boot ID and stream ID are required")
	}
	var eventSequence int64
	if err := s.db.QueryRowContext(ctx, `
SELECT COALESCE(MAX(sequence), 0)
FROM events
WHERE boot_id = ? AND stream_id = ?`, bootID, streamID).Scan(&eventSequence); err != nil {
		return 0, fmt.Errorf("storage: read last event sequence: %w", err)
	}
	var metadataSequence int64
	err := s.db.QueryRowContext(ctx,
		`SELECT CAST(value AS INTEGER) FROM metadata WHERE key = ?`,
		sequenceMetadataKey(bootID, streamID),
	).Scan(&metadataSequence)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, fmt.Errorf("storage: read sequence watermark: %w", err)
	}
	sequence := eventSequence
	if metadataSequence > sequence {
		sequence = metadataSequence
	}
	if sequence < 0 {
		return 0, errors.New("storage: stored event sequence is negative")
	}
	return uint64(sequence), nil
}

func (s *Store) recordSequence(ctx context.Context, event model.Event) error {
	if event.BootID == "" || event.StreamID == "" || event.Sequence == 0 {
		return nil
	}
	key := sequenceMetadataKey(event.BootID, event.StreamID)
	value := fmt.Sprintf("%d", event.Sequence)
	_, err := s.executor().ExecContext(ctx, `
INSERT INTO metadata(key, value, updated_at_ns)
VALUES (?, ?, ?)
ON CONFLICT(key) DO UPDATE SET
    value = CASE
        WHEN CAST(metadata.value AS INTEGER) < CAST(excluded.value AS INTEGER)
        THEN excluded.value ELSE metadata.value END,
    updated_at_ns = CASE
        WHEN CAST(metadata.value AS INTEGER) < CAST(excluded.value AS INTEGER)
        THEN excluded.updated_at_ns ELSE metadata.updated_at_ns END`,
		key, value, time.Now().UTC().UnixNano(),
	)
	if err != nil {
		return fmt.Errorf("storage: record sequence watermark: %w", err)
	}
	return nil
}

func sequenceMetadataKey(bootID, streamID string) string {
	return "sequence:" + bootID + ":" + streamID
}

// DeleteEventsBefore deletes at most limit old events that are not evidence
// for a finding. It is intended for small periodic retention batches.
func (s *Store) DeleteEventsBefore(ctx context.Context, cutoff time.Time, limit int) (int64, error) {
	if cutoff.IsZero() {
		return 0, errors.New("storage: retention cutoff is required")
	}
	limit, err := boundedLimit(limit)
	if err != nil {
		return 0, err
	}
	result, err := s.db.ExecContext(ctx, `
DELETE FROM events
WHERE event_id IN (
    SELECT e.event_id
    FROM events e
    WHERE e.event_time_ns < ?
      AND NOT EXISTS (SELECT 1 FROM finding_events fe WHERE fe.event_id = e.event_id)
    ORDER BY e.event_time_ns
    LIMIT ?
)`, cutoff.UnixNano(), limit)
	if err != nil {
		return 0, fmt.Errorf("storage: delete expired events: %w", err)
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("storage: inspect expired event deletion: %w", err)
	}
	return deleted, nil
}

func decodeEvent(body []byte) (model.Event, error) {
	var event model.Event
	if err := json.Unmarshal(body, &event); err != nil {
		return model.Event{}, fmt.Errorf("storage: decode stored event: %w", err)
	}
	return event, nil
}

func boundedLimit(limit int) (int, error) {
	if limit == 0 {
		return 100, nil
	}
	if limit < 0 || limit > 100_000 {
		return 0, fmt.Errorf("storage: query limit must be between 1 and 100000")
	}
	return limit, nil
}

func isContextObservation(kind string) bool {
	return kind == "process.exec_observation" || kind == "file.write" || kind == "network.connect"
}

func clearDerivedContext(process *model.Process) {
	process.OriginService = ""
	process.LineageConfidence = ""
	process.Complete = false
}
