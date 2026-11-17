package webpanel

import (
	"context"
	"net/http"
	"xe-antishell/internal/hostmetrics"
)

type resourceClient interface {
	Resources(context.Context) (hostmetrics.Snapshot, error)
}

func (s *Server) resources(w http.ResponseWriter, r *http.Request) {
	client, ok := s.agent.(resourceClient)
	if !ok {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "resource sampling unavailable"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()
	value, err := client.Resources(ctx)
	if err != nil {
		s.upstreamError(w, "resources", err)
		return
	}
	writeJSON(w, http.StatusOK, value)
}
