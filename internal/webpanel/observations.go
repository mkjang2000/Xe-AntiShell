package webpanel

import (
	"context"
	"net/http"

	"xe-antishell/internal/model"
)

type observationClient interface {
	Observations(context.Context, model.ObservationQuery) (model.ObservationReport, error)
}

func (s *Server) observations(w http.ResponseWriter, r *http.Request) {
	query, err := model.ParseObservationQuery(r.URL.Query())
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	client, ok := s.agent.(observationClient)
	if !ok {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "observation reports unavailable"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()
	report, err := client.Observations(ctx, query)
	if err != nil {
		s.upstreamError(w, "observation samples", err)
		return
	}
	writeJSON(w, http.StatusOK, report)
}
