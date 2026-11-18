package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"math"
	"time"
)

const eventSweepKey = "retention:event_time_sweep"
const maxEventSweepPage = 1000

// The existing descending event-time index orders equal timestamps by rowid.
// Both branches seek into that index, including when thousands of events
// share a timestamp. The first page starts strictly before the cutoff.
const eventSweepPage = `SELECT rowid, event_time_ns FROM events WHERE event_time_ns=?1 AND rowid>?2
UNION ALL SELECT rowid, event_time_ns FROM events WHERE event_time_ns<?1
ORDER BY event_time_ns DESC, rowid ASC LIMIT ?3`

const lastEventInFullPage = "SELECT rowid, event_time_ns FROM (" + eventSweepPage + ") LIMIT 1 OFFSET (?3-1)"
const deleteEventPage = "WITH page AS MATERIALIZED (" + eventSweepPage + `)
DELETE FROM events AS e WHERE e.rowid IN (SELECT rowid FROM page)` + unreferencedEvent

type eventSweepCursor struct {
	RowID  int64 `json:"rowid"`
	TimeNS int64 `json:"time_ns"`
}

// SweepEventsBefore inspects at most limit expired events. The cursor advances
// even across a fully protected page. A new pass revisits events whose delivery
// has since been acknowledged and late inserts above the previous cursor.
func (s *Store) SweepEventsBefore(ctx context.Context, cutoff time.Time, limit int) (bool, error) {
	if cutoff.IsZero() || limit < 1 || limit > maxEventSweepPage {
		return false, errors.New("storage: invalid event sweep cutoff or page size")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	var saved []byte
	var cursor eventSweepCursor
	err = tx.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key=?", eventSweepKey).Scan(&saved)
	switch {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return false, err
	default:
		if err := json.Unmarshal(saved, &cursor); err != nil || cursor.RowID <= 0 {
			return false, errors.New("storage: invalid event sweep cursor")
		}
	}
	// A longer retention setting or a clock rollback can move the cutoff
	// behind a saved cursor. Never delete an event protected by today's cutoff.
	if saved == nil || cursor.TimeNS >= cutoff.UnixNano() {
		cursor = eventSweepCursor{RowID: math.MaxInt64, TimeNS: cutoff.UnixNano()}
	}

	var next eventSweepCursor
	err = tx.QueryRowContext(ctx, lastEventInFullPage, cursor.TimeNS, cursor.RowID, limit).Scan(&next.RowID, &next.TimeNS)
	fullPage := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, deleteEventPage, cursor.TimeNS, cursor.RowID, limit); err != nil {
		return false, err
	}
	if fullPage {
		value, err := json.Marshal(next)
		if err != nil {
			return false, err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO metadata(key,value,updated_at_ns) VALUES(?,?,?)
ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at_ns=excluded.updated_at_ns`,
			eventSweepKey, value, time.Now().UnixNano())
		if err != nil {
			return false, err
		}
	} else if saved != nil {
		if _, err := tx.ExecContext(ctx, "DELETE FROM metadata WHERE key=?", eventSweepKey); err != nil {
			return false, err
		}
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return fullPage, nil
}
