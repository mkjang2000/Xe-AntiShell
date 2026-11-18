package localapi

import (
	"context"
	"errors"
	"net/http"

	"xe-antishell/internal/model"
)

type rulesBackend interface {
	Rules(context.Context) (model.RuleCatalog, error)
}

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	backend, ok := s.backend.(rulesBackend)
	if !ok {
		writeError(w, http.StatusNotImplemented, errors.New("rule catalog unavailable"))
		return
	}
	result, err := backend.Rules(r.Context())
	s.writeResult(w, result, err)
}

func (c *Client) Rules(ctx context.Context) (model.RuleCatalog, error) {
	var catalog model.RuleCatalog
	err := c.get(ctx, "/v1/rules", &catalog)
	return catalog, err
}
