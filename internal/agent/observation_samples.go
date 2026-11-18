package agent

import (
	"context"

	"xe-antishell/internal/model"
)

func (s *Service) Observations(ctx context.Context, q model.ObservationQuery) (model.ObservationReport, error) {
	return s.store.ObservationSamples(ctx, q)
}
