package webpanel

import (
	"context"
	"net/http"

	"xe-antishell/internal/model"
)

type summaryClient interface {
	Summary(context.Context) (model.OperatorSummary, error)
}

func (s *Server) summary(w http.ResponseWriter, r *http.Request) {
	client, ok := s.agent.(summaryClient)
	if !ok {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "operator summary unavailable"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()
	value, err := client.Summary(ctx)
	if err != nil {
		s.upstreamError(w, "operator summary", err)
		return
	}
	writeJSON(w, http.StatusOK, value)
}
