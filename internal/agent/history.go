package agent

import (
	"context"
	"xe-antishell/internal/model"
)

func (s *Service) History(ctx context.Context, query model.HistoryQuery) (model.HistoryPage, error) {
	return s.store.History(ctx, query)
}
func (s *Service) Services(ctx context.Context) ([]model.ServiceSummary, error) {
	return s.store.Services(ctx)
}
