package localapi

import (
	"context"
	"errors"
	"net/http"

	"xe-antishell/internal/model"
)

type summaryBackend interface {
	Summary(context.Context) (model.OperatorSummary, error)
}

func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	backend, ok := s.backend.(summaryBackend)
	if !ok {
		writeError(w, http.StatusNotImplemented, errors.New("operator summary unavailable"))
		return
	}
	value, err := backend.Summary(r.Context())
	s.writeResult(w, value, err)
}

func (c *Client) Summary(ctx context.Context) (model.OperatorSummary, error) {
	var result model.OperatorSummary
	err := c.get(ctx, "/v1/summary", &result)
	return result, err
}
