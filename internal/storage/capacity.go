package storage

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"syscall"
	"time"
)

// Limit rows inspected even if a long prefix of old evidence is pinned by
// findings. A capped scan reports a lower bound on the eligible event count.
const backlogScanLimit = 1000

type CapacitySnapshot struct {
	UTCDay             string
	MeasurementStarted time.Time
	EventsToday        int64
	BytesToday         int64
	EventsYesterday    int64
	BytesYesterday     int64
	YesterdayObserved  bool
	DatabaseBytes      *int64
	WALBytes           *int64
	DiskAvailableBytes *uint64
	OldestEvent        *time.Time
	RetentionBacklog   int
	BacklogTruncated   bool
}

// Capacity measures actual stored JSON bytes on first insertion. Filesystem
// metrics are unavailable for private in-memory stores.
func (s *Store) Capacity(ctx context.Context, now, cutoff time.Time) (CapacitySnapshot, error) {
	now = now.UTC()
	c := CapacitySnapshot{UTCDay: now.Format(time.DateOnly)}
	var oldest sql.NullInt64
	var measured int64
	err := s.db.QueryRowContext(ctx, `
WITH candidates AS MATERIALIZED (
  SELECT event_id FROM events WHERE event_time_ns<?1 ORDER BY event_time_ns LIMIT ?2
), expired AS (SELECT event_id FROM candidates LIMIT ?3)
SELECT applied_at_ns,
       coalesce(today.stored_events,0), coalesce(today.stored_bytes,0),
       coalesce(prev.stored_events,0), coalesce(prev.stored_bytes,0),
       (SELECT min(event_time_ns) FROM events),
       (SELECT count(*) FROM candidates)>?3,
       (SELECT count(*) FROM expired e WHERE NOT EXISTS (SELECT 1 FROM finding_events f WHERE f.event_id=e.event_id)
          AND NOT EXISTS (SELECT 1 FROM delivery_outbox d WHERE d.kind='event_bundle' AND d.record_id=e.event_id))
FROM schema_migrations
LEFT JOIN daily_event_storage today ON today.utc_day=?4
LEFT JOIN daily_event_storage prev ON prev.utc_day=?5
WHERE version=4`, cutoff.UnixNano(), backlogScanLimit+1, backlogScanLimit, c.UTCDay, now.AddDate(0, 0, -1).Format(time.DateOnly)).
		Scan(&measured, &c.EventsToday, &c.BytesToday, &c.EventsYesterday, &c.BytesYesterday,
			&oldest, &c.BacklogTruncated, &c.RetentionBacklog)
	if err != nil {
		return c, err
	}
	c.MeasurementStarted = time.Unix(0, measured).UTC()
	c.YesterdayObserved = c.MeasurementStarted.Before(now.Truncate(24 * time.Hour))
	if oldest.Valid {
		at := time.Unix(0, oldest.Int64).UTC()
		c.OldestEvent = &at
	}
	if s.path != "" {
		c.DatabaseBytes = fileSize(s.path, false)
		c.WALBytes = fileSize(s.path+"-wal", true)
		var stat syscall.Statfs_t
		if syscall.Statfs(s.path, &stat) == nil && stat.Bsize > 0 {
			available := stat.Bavail * uint64(stat.Bsize)
			c.DiskAvailableBytes = &available
		}
	}
	return c, nil
}

func fileSize(path string, optional bool) *int64 {
	info, err := os.Stat(path)
	if optional && errors.Is(err, os.ErrNotExist) {
		return new(int64)
	}
	if err != nil {
		return nil
	}
	size := info.Size()
	return &size
}
