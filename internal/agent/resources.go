package agent

import (
	"context"
	"xe-antishell/internal/hostmetrics"
)

func (s *Service) Resources(ctx context.Context) (hostmetrics.Snapshot, error) {
	monitoring := s.currentMonitoring()
	if !monitoring.Enabled {
		return hostmetrics.Snapshot{Errors: []string{"monitoring disabled by policy"}}, nil
	}
	return s.metrics.Sample(ctx, monitoring.ProcessLimit), ctx.Err()
}
