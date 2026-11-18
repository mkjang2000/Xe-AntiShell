package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// These predicates match the partial reference indexes. The caller excludes
// legacy empty process keys so references with no attributed process stay safe.
const unreferencedProcess = `
  AND p.process_key <> ''
  AND NOT EXISTS (SELECT 1 FROM events e WHERE e.process_key <> '' AND e.process_key = p.process_key)
  AND NOT EXISTS (SELECT 1 FROM findings f WHERE f.process_key <> '' AND f.process_key = p.process_key)`

const processSweepKey = "retention:process_rowid_sweep"
const maxProcessSweepPage = 1000

const processPageBounds = `SELECT count(*),coalesce(max(rowid),0) FROM (
    SELECT rowid FROM processes WHERE rowid>? AND rowid<=? ORDER BY rowid LIMIT ?
)`
const deleteProcessPage = `DELETE FROM processes AS p
WHERE p.rowid>? AND p.rowid<=? AND p.last_seen_ns<?` + unreferencedProcess

type processSweepCursor struct {
	After   int64 `json:"after"`
	Through int64 `json:"through"`
}

// SweepProcessesBefore examines at most limit rows in one transaction. More
// refers to the fixed sweep range, including pages with no deletable rows.
// The cursor survives restarts and advances atomically with the deletion.
func (s *Store) SweepProcessesBefore(ctx context.Context, cutoff time.Time, limit int) (bool, error) {
	if cutoff.IsZero() || limit < 1 || limit > maxProcessSweepPage {
		return false, errors.New("storage: invalid process sweep cutoff or page size")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	var cursor processSweepCursor
	var raw []byte
	err = tx.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key=?", processSweepKey).Scan(&raw)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		// Freeze this pass's upper bound so continuing inserts cannot defer the
		// next visit to older processes that were referenced on an earlier pass.
		err = tx.QueryRowContext(ctx, "SELECT coalesce(max(rowid),0) FROM processes").Scan(&cursor.Through)
	case err == nil:
		err = json.Unmarshal(raw, &cursor)
		if err == nil && (cursor.After <= 0 || cursor.After >= cursor.Through) {
			return false, errors.New("storage: invalid process sweep cursor")
		}
	}
	if err != nil {
		return false, fmt.Errorf("storage: read process sweep cursor: %w", err)
	}

	var inspected int
	var last int64
	if err := tx.QueryRowContext(ctx, processPageBounds, cursor.After, cursor.Through, limit).Scan(&inspected, &last); err != nil {
		return false, err
	}
	if inspected > 0 {
		if _, err := tx.ExecContext(ctx, deleteProcessPage, cursor.After, last, cutoff.UnixNano()); err != nil {
			return false, fmt.Errorf("storage: delete process page: %w", err)
		}
	}
	more := inspected == limit && last < cursor.Through
	if more {
		cursor.After = last
		encoded, err := json.Marshal(cursor)
		if err != nil {
			return false, err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO metadata(key,value,updated_at_ns) VALUES(?,?,?)
ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at_ns=excluded.updated_at_ns`, processSweepKey, encoded, time.Now().UTC().UnixNano())
		if err != nil {
			return false, err
		}
	} else if raw != nil {
		if _, err := tx.ExecContext(ctx, "DELETE FROM metadata WHERE key=?", processSweepKey); err != nil {
			return false, err
		}
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return more, nil
}
