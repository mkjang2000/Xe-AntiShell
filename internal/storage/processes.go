package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"xe-antishell/internal/model"
)

// SaveProcess inserts or updates a boot-scoped process observation. bootID is
// explicit because Process deliberately contains only the derived process key.
func (s *Store) SaveProcess(ctx context.Context, bootID string, process model.Process) error {
	if bootID == "" {
		return errors.New("storage: process boot ID is required")
	}
	if process.Key == "" {
		return errors.New("storage: process key is required")
	}
	if process.PID < 1 {
		return errors.New("storage: process PID must be positive")
	}
	if process.StartTime.IsZero() || process.FirstSeen.IsZero() || process.LastSeen.IsZero() {
		return errors.New("storage: process start, first-seen, and last-seen times are required")
	}
	if process.LastSeen.Before(process.FirstSeen) {
		return errors.New("storage: process last-seen time precedes first-seen time")
	}

	body, err := json.Marshal(process)
	if err != nil {
		return fmt.Errorf("storage: encode process %q: %w", process.Key, err)
	}
	exitedAt := int64(0)
	if process.ExitedAt != nil {
		exitedAt = process.ExitedAt.UnixNano()
	}
	result, err := s.executor().ExecContext(ctx, `
INSERT INTO processes(
    process_key, parent_key, boot_id, exec_id, pid, ppid, start_time_ns,
    exe, origin_service, complete, first_seen_ns, last_seen_ns,
    exited_at_ns, process_json
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(process_key) DO UPDATE SET
    parent_key = excluded.parent_key,
    exec_id = excluded.exec_id,
    pid = excluded.pid,
    ppid = excluded.ppid,
    start_time_ns = excluded.start_time_ns,
    exe = excluded.exe,
    origin_service = excluded.origin_service,
    complete = excluded.complete,
    first_seen_ns = excluded.first_seen_ns,
    last_seen_ns = excluded.last_seen_ns,
    exited_at_ns = excluded.exited_at_ns,
    process_json = excluded.process_json
WHERE processes.boot_id = excluded.boot_id`,
		process.Key, process.ParentKey, bootID, process.ExecID, process.PID,
		process.PPID, process.StartTime.UnixNano(), process.Exe,
		process.OriginService, process.Complete, process.FirstSeen.UnixNano(),
		process.LastSeen.UnixNano(), exitedAt, body,
	)
	if err != nil {
		return fmt.Errorf("storage: save process %q: %w", process.Key, err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("storage: inspect process save %q: %w", process.Key, err)
	}
	if changed == 0 {
		return fmt.Errorf("%w: process key %q belongs to another boot", ErrConflict, process.Key)
	}
	return nil
}

// GetProcess returns a process by its boot-scoped process key.
func (s *Store) GetProcess(ctx context.Context, processKey string) (model.Process, error) {
	var body []byte
	err := s.db.QueryRowContext(ctx, `SELECT process_json FROM processes WHERE process_key = ?`, processKey).Scan(&body)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Process{}, fmt.Errorf("%w: process %q", ErrNotFound, processKey)
	}
	if err != nil {
		return model.Process{}, fmt.Errorf("storage: get process %q: %w", processKey, err)
	}
	return decodeProcess(body)
}

// FindLatestProcessByPID resolves PID reuse by restricting the query to a boot
// and returning the newest observation. last_seen_ns breaks ties for audit
// execs that share the same millisecond-resolution event timestamp.
func (s *Store) FindLatestProcessByPID(ctx context.Context, bootID string, pid int) (model.Process, error) {
	if bootID == "" || pid < 1 {
		return model.Process{}, errors.New("storage: boot ID and positive PID are required")
	}
	var body []byte
	err := s.db.QueryRowContext(ctx, `
SELECT process_json
FROM processes
WHERE boot_id = ? AND pid = ?
ORDER BY start_time_ns DESC, last_seen_ns DESC, process_key DESC
LIMIT 1`, bootID, pid).Scan(&body)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Process{}, fmt.Errorf("%w: PID %d in boot %q", ErrNotFound, pid, bootID)
	}
	if err != nil {
		return model.Process{}, fmt.Errorf("storage: find PID %d: %w", pid, err)
	}
	return decodeProcess(body)
}

// ListChildProcesses returns direct children ordered by start time.
func (s *Store) ListChildProcesses(ctx context.Context, parentKey string, limit int) ([]model.Process, error) {
	limit, err := boundedLimit(limit)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT process_json
FROM processes
WHERE parent_key = ?
ORDER BY start_time_ns, process_key
LIMIT ?`, parentKey, limit)
	if err != nil {
		return nil, fmt.Errorf("storage: list children of %q: %w", parentKey, err)
	}
	defer rows.Close()

	processes := make([]model.Process, 0)
	for rows.Next() {
		var body []byte
		if err := rows.Scan(&body); err != nil {
			return nil, fmt.Errorf("storage: scan child process: %w", err)
		}
		process, err := decodeProcess(body)
		if err != nil {
			return nil, err
		}
		processes = append(processes, process)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("storage: iterate child processes: %w", err)
	}
	return processes, nil
}

// ListActiveProcesses returns non-exited processes for one boot in start-time
// order so a restarted agent can restore its in-memory lineage map.
func (s *Store) ListActiveProcesses(ctx context.Context, bootID string, limit int) ([]model.Process, error) {
	if bootID == "" {
		return nil, errors.New("storage: boot ID is required")
	}
	limit, err := boundedLimit(limit)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT process_json
FROM processes
WHERE boot_id = ? AND exited_at_ns = 0
ORDER BY start_time_ns, process_key
LIMIT ?`, bootID, limit)
	if err != nil {
		return nil, fmt.Errorf("storage: list active processes: %w", err)
	}
	defer rows.Close()
	processes := make([]model.Process, 0)
	for rows.Next() {
		var body []byte
		if err := rows.Scan(&body); err != nil {
			return nil, fmt.Errorf("storage: scan active process: %w", err)
		}
		process, err := decodeProcess(body)
		if err != nil {
			return nil, err
		}
		processes = append(processes, process)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("storage: iterate active processes: %w", err)
	}
	return processes, nil
}

// DeleteProcessesBefore deletes a bounded batch of old process observations
// only after every retained event and finding has stopped referring to them.
// Audit input has no process-exit stream, so exited_at alone cannot be used as
// an indication that a row is safe to remove.
func (s *Store) DeleteProcessesBefore(ctx context.Context, cutoff time.Time, limit int) (int64, error) {
	if cutoff.IsZero() {
		return 0, errors.New("storage: process retention cutoff is required")
	}
	limit, err := boundedLimit(limit)
	if err != nil {
		return 0, err
	}
	result, err := s.db.ExecContext(ctx, `
DELETE FROM processes
WHERE process_key IN (
    SELECT p.process_key
    FROM processes p
    WHERE p.last_seen_ns < ?`+unreferencedProcess+`
    ORDER BY p.last_seen_ns, p.process_key
    LIMIT ?
)`, cutoff.UnixNano(), limit)
	if err != nil {
		return 0, fmt.Errorf("storage: delete expired processes: %w", err)
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("storage: inspect expired process deletion: %w", err)
	}
	return deleted, nil
}

func decodeProcess(body []byte) (model.Process, error) {
	var process model.Process
	if err := json.Unmarshal(body, &process); err != nil {
		return model.Process{}, fmt.Errorf("storage: decode stored process: %w", err)
	}
	return process, nil
}
