package webpanel

import (
	"context"
	"net/http"
	"strconv"

	"xe-antishell/internal/model"
)

type historyClient interface {
	History(context.Context, model.HistoryQuery) (model.HistoryPage, error)
	Services(context.Context) ([]model.ServiceSummary, error)
}

func (s *Server) history(w http.ResponseWriter, r *http.Request) {
	client, ok := s.agent.(historyClient)
	if !ok {
		writeJSON(w, 501, map[string]string{"error": "history unavailable"})
		return
	}
	values := r.URL.Query()
	excludeSelfTests := false
	if raw := values.Get("exclude_self_tests"); raw != "" {
		var err error
		excludeSelfTests, err = strconv.ParseBool(raw)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid self-test filter"})
			return
		}
	}
	limit := 10
	if raw := values.Get("limit"); raw != "" {
		var err error
		limit, err = strconv.Atoi(raw)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid limit"})
			return
		}
	}
	if limit < 1 || limit > 100 || len(values.Get("q")) > 256 || len(values.Get("cursor")) > 2048 {
		writeJSON(w, 400, map[string]string{"error": "invalid history query"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()
	page, err := client.History(ctx, model.HistoryQuery{Kind: values.Get("kind"), Service: values.Get("service"), Search: values.Get("q"), Severity: values.Get("severity"), Cursor: values.Get("cursor"), Limit: limit, ExcludeSelfTests: excludeSelfTests})
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "history query failed; check filters or reload the first page"})
		return
	}
	writeJSON(w, 200, page)
}
func (s *Server) services(w http.ResponseWriter, r *http.Request) {
	client, ok := s.agent.(historyClient)
	if !ok {
		writeJSON(w, 501, map[string]string{"error": "history unavailable"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()
	items, err := client.Services(ctx)
	if err != nil {
		s.upstreamError(w, "services", err)
		return
	}
	writeJSON(w, 200, items)
}
