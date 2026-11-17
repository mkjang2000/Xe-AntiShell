package agent

import (
	"context"
	"fmt"
	"time"
)

const retentionInterval = 6 * time.Hour
const retentionBatchSize = 1000
const maxRetentionBatchesPerRun = 10
const retentionStartupDelay = 30 * time.Second
const retentionBatchPause = 100 * time.Millisecond

func (s *Service) retentionLoop(ctx context.Context) {
	defer s.producerWG.Done()
	run := func() {
		cutoff := time.Now().UTC().AddDate(0, 0, -s.config.Limits.RetentionDays)
		for batch := 0; batch < maxRetentionBatchesPerRun; batch++ {
			deleted, err := s.store.DeleteEventsBefore(ctx, cutoff, retentionBatchSize)
			if err != nil {
				if ctx.Err() == nil {
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
		for batch := 0; batch < maxRetentionBatchesPerRun; batch++ {
			deleted, err := s.store.DeleteProcessesBefore(ctx, cutoff, retentionBatchSize)
			if err != nil {
				if ctx.Err() == nil {
					s.recordOperationalError(fmt.Errorf("process retention: %w", err))
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
		s.clearOperationError("retention")
	}
	if !managedWait(ctx, retentionStartupDelay) {
		return
	}
	run()
	ticker := time.NewTicker(retentionInterval)
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
