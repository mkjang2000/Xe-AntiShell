package localapi

import (
	"context"
	"net/http"
	"xe-antishell/internal/hostmetrics"
)

type resourceBackend interface {
	Resources(context.Context) (hostmetrics.Snapshot, error)
}

func (s *Server) handleResources(w http.ResponseWriter, r *http.Request) {
	backend, ok := s.backend.(resourceBackend)
	if !ok {
		http.Error(w, "resource sampling unavailable", http.StatusNotImplemented)
		return
	}
	value, err := backend.Resources(r.Context())
	s.writeResult(w, value, err)
}
func (c *Client) Resources(ctx context.Context) (hostmetrics.Snapshot, error) {
	var value hostmetrics.Snapshot
	err := c.get(ctx, "/v1/resources", &value)
	return value, err
}
