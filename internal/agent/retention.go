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
	if minutes := s.observationHistoryMinutes(); minutes > 0 {
		return now.Add(-time.Duration(minutes) * time.Minute)
	}
	return now.AddDate(0, 0, -s.config.Limits.RetentionDays)
}

func (s *Service) retentionLoop(ctx context.Context) {
	defer s.producerWG.Done()
	run := func() {
		sweeps := []struct {
			name     string
			pageSize int
			page     func(context.Context, time.Time, int) (bool, error)
		}{
			{"event", retentionBatchSize, s.store.SweepEventsBefore},
			{"process", processSweepPageSize, s.store.SweepProcessesBefore},
		}
		for _, sweep := range sweeps {
			pageSize := sweep.pageSize
			for pages := 0; pages < maxRetentionBatchesPerRun*retentionBatchSize/sweep.pageSize; pages++ {
				s.agentConfigurationMu.Lock()
				pageCtx, cancel := context.WithTimeout(ctx, retentionBatchDeadline)
				more, err := sweep.page(pageCtx, s.observationCutoff(time.Now().UTC()), pageSize)
				timedOut := errors.Is(pageCtx.Err(), context.DeadlineExceeded)
				cancel()
				s.agentConfigurationMu.Unlock()
				if err != nil {
					if ctx.Err() != nil {
						return
					}
					if !timedOut {
						s.recordOperationalError(fmt.Errorf("%s retention: %w", sweep.name, err))
						return
					}
					// A cancelled transaction preserves its last committed cursor.
					pageSize = max(1, pageSize/2)
				} else if !more {
					break
				}
				if !managedWait(ctx, retentionBatchPause) {
					return
				}
			}
		}
		s.clearOperationError("retention")
	}
	if !managedWait(ctx, retentionStartupDelay) {
		return
	}
	run()
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	last := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if s.observationHistoryMinutes() > 0 || time.Since(last) >= retentionInterval {
				run()
				last = time.Now()
			}
		}
	}
}
