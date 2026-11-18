package localapi

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"

	"xe-antishell/internal/model"
)

func (s *Server) handleObservations(w http.ResponseWriter, r *http.Request) {
	q, err := model.ParseObservationQuery(r.URL.Query())
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	backend, ok := s.backend.(interface {
		Observations(context.Context, model.ObservationQuery) (model.ObservationReport, error)
	})
	if !ok {
		writeError(w, http.StatusNotImplemented, errors.New("observation samples unavailable"))
		return
	}
	report, err := backend.Observations(r.Context(), q)
	s.writeResult(w, report, err)
}

func (c *Client) Observations(ctx context.Context, q model.ObservationQuery) (model.ObservationReport, error) {
	var report model.ObservationReport
	if err := q.Validate(); err != nil {
		return report, err
	}
	values := url.Values{}
	if q.Limit != 0 {
		values.Set("limit", strconv.Itoa(q.Limit))
	}
	if q.Service != "" {
		values.Set("service", q.Service)
	}
	if q.ProtectedDir != "" {
		values.Set("protected_dir", q.ProtectedDir)
	}
	if q.AllowedDir != "" {
		values.Set("allowed_dir", q.AllowedDir)
	}
	err := c.get(ctx, "/v1/observations?"+values.Encode(), &report)
	return report, err
}
