package agent

import (
	"context"
	"errors"
	"fmt"
	"time"
)

const retentionInterval = 6 * time.Hour
const retentionBatchSize = 1000
const maxRetentionBatchesPerRun = 10
const retentionStartupDelay = 30 * time.Second
const retentionBatchPause = 100 * time.Millisecond
const processSweepPageSize = 250
const retentionBatchDeadline = 400 * time.Millisecond

func (s *Service) observationCutoff(now time.Time) time.Time {
	if minutes := s.config.Limits.ObservationHistoryMinutes; minutes > 0 {
		return now.Add(-time.Duration(minutes) * time.Minute)
	}
	return now.AddDate(0, 0, -s.config.Limits.RetentionDays)
}

func (s *Service) retentionLoop(ctx context.Context) {
	defer s.producerWG.Done()
	run := func() {
		cutoff := s.observationCutoff(time.Now().UTC())
		for batch := 0; batch < maxRetentionBatchesPerRun; batch++ {
			batchCtx, cancel := context.WithTimeout(ctx, retentionBatchDeadline)
			deleted, err := s.store.DeleteEventsBefore(batchCtx, cutoff, retentionBatchSize)
			timedOut := errors.Is(batchCtx.Err(), context.DeadlineExceeded)
			cancel()
			if err != nil {
				if ctx.Err() == nil && !timedOut {
					s.recordOperationalError(fmt.Errorf("event retention: %w", err))
				}
				return
			}
			if deleted < retentionBatchSize {
				break
			}
			if !managedWait(ctx, retentionBatchPause) {
				return
			}
		}
		// Keep the existing per-run row budget but bound every individual
		// writer reservation and yield to ingestion between pages.
		pageSize := processSweepPageSize
		for pages := 0; pages < maxRetentionBatchesPerRun*retentionBatchSize/processSweepPageSize; pages++ {
			pageCtx, cancel := context.WithTimeout(ctx, retentionBatchDeadline)
			more, err := s.store.SweepProcessesBefore(pageCtx, cutoff, pageSize)
			timedOut := errors.Is(pageCtx.Err(), context.DeadlineExceeded)
			cancel()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				if !timedOut {
					s.recordOperationalError(fmt.Errorf("process retention: %w", err))
					return
				}
				// A cold or busy DB can yield mid-page. The transaction kept its
				// previous cursor; retry smaller pages after giving writers time.
				pageSize = max(1, pageSize/2)
			} else if !more {
				break
			}
			if !managedWait(ctx, retentionBatchPause) {
				return
			}
		}
		s.clearOperationError("retention")
	}
	if !managedWait(ctx, retentionStartupDelay) {
		return
	}
	run()
	interval := retentionInterval
	if s.config.Limits.ObservationHistoryMinutes > 0 {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		}
	}
}
