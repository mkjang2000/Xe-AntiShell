package localapi

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"

	"xe-antishell/internal/model"
)

type historyBackend interface {
	History(context.Context, model.HistoryQuery) (model.HistoryPage, error)
	Services(context.Context) ([]model.ServiceSummary, error)
}

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	backend, ok := s.backend.(historyBackend)
	if !ok {
		writeError(w, http.StatusNotImplemented, errors.New("history unavailable"))
		return
	}
	values := r.URL.Query()
	excludeSelfTests := false
	if raw := values.Get("exclude_self_tests"); raw != "" {
		var err error
		excludeSelfTests, err = strconv.ParseBool(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, errors.New("invalid self-test filter"))
			return
		}
	}
	limit := 10
	if raw := values.Get("limit"); raw != "" {
		var err error
		limit, err = strconv.Atoi(raw)
		if err != nil {
			writeError(w, 400, errors.New("invalid limit"))
			return
		}
	}
	query := model.HistoryQuery{Kind: values.Get("kind"), Service: values.Get("service"), Search: values.Get("q"), Severity: values.Get("severity"), Cursor: values.Get("cursor"), Limit: limit, ExcludeSelfTests: excludeSelfTests}
	page, err := backend.History(r.Context(), query)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.writeResult(w, page, nil)
}
func (s *Server) handleServices(w http.ResponseWriter, r *http.Request) {
	backend, ok := s.backend.(historyBackend)
	if !ok {
		writeError(w, 501, errors.New("history unavailable"))
		return
	}
	value, err := backend.Services(r.Context())
	s.writeResult(w, value, err)
}

func (c *Client) History(ctx context.Context, q model.HistoryQuery) (model.HistoryPage, error) {
	var result model.HistoryPage
	values := url.Values{"kind": {q.Kind}, "service": {q.Service}, "q": {q.Search}, "severity": {q.Severity}, "cursor": {q.Cursor}, "limit": {strconv.Itoa(q.Limit)}}
	if q.ExcludeSelfTests {
		values.Set("exclude_self_tests", "1")
	}
	err := c.get(ctx, "/v1/history?"+values.Encode(), &result)
	return result, err
}
func (c *Client) Services(ctx context.Context) ([]model.ServiceSummary, error) {
	var result []model.ServiceSummary
	err := c.get(ctx, "/v1/services", &result)
	return result, err
}
