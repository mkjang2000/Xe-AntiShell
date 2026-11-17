package localapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"xe-antishell/internal/model"
)

type operatorBackend struct {
	*fakeBackend
	summary model.OperatorSummary
	err     error
	query   model.HistoryQuery
}

func (b *operatorBackend) Summary(context.Context) (model.OperatorSummary, error) {
	return b.summary, b.err
}
func (b *operatorBackend) History(_ context.Context, q model.HistoryQuery) (model.HistoryPage, error) {
	b.query = q
	return model.HistoryPage{Items: json.RawMessage("[]")}, nil
}
func (b *operatorBackend) Services(context.Context) ([]model.ServiceSummary, error) { return nil, nil }

func TestOperatorSummaryRouteAndFailure(t *testing.T) {
	backend := &operatorBackend{fakeBackend: &fakeBackend{}, summary: model.OperatorSummary{TotalEvents: 333, OpenFindings: 22, RecentFindings: []model.Finding{}}}
	server := NewServer(backend, 100, 1000, 1<<20)
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/summary", nil))
	var summary model.OperatorSummary
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &summary) != nil || summary.TotalEvents != 333 || summary.OpenFindings != 22 {
		t.Fatalf("summary route: %d %s", response.Code, response.Body.String())
	}
	backend.err = errors.New("unavailable")
	response = httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/summary", nil))
	if response.Code != 500 {
		t.Fatalf("failed summary became successful zero totals: %d %s", response.Code, response.Body.String())
	}
	server = NewServer(&fakeBackend{}, 100, 1000, 1<<20)
	response = httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/summary", nil))
	if response.Code != http.StatusNotImplemented {
		t.Fatalf("unsupported backend: %d", response.Code)
	}
}

func TestHistorySelfTestFilterParsesAndRejectsInvalidBoolean(t *testing.T) {
	backend := &operatorBackend{fakeBackend: &fakeBackend{}}
	server := NewServer(backend, 100, 1000, 1<<20)
	for _, raw := range []string{"1", "true", "0", "false", ""} {
		response := httptest.NewRecorder()
		server.httpServer.Handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/history?kind=findings&exclude_self_tests="+raw, nil))
		if response.Code != 200 || backend.query.ExcludeSelfTests != (raw == "1" || raw == "true") {
			t.Fatalf("filter %q parsed incorrectly: %d %+v", raw, response.Code, backend.query)
		}
	}
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/history?kind=findings&exclude_self_tests=maybe", nil))
	if response.Code != 400 {
		t.Fatalf("invalid boolean: %d", response.Code)
	}
}

type operatorTransport func(*http.Request) (*http.Response, error)

func (f operatorTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestOperatorClientRetainsFilterAndDecodesSummary(t *testing.T) {
	var seenFilter string
	client := &Client{http: &http.Client{Transport: operatorTransport(func(r *http.Request) (*http.Response, error) {
		body := `{"items":[],"total":0}`
		if r.URL.Path == "/v1/summary" {
			body = `{"total_events":44,"open_findings":11,"recent_findings":[]}`
		} else {
			seenFilter = r.URL.Query().Get("exclude_self_tests")
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
	})}}
	if _, err := client.History(context.Background(), model.HistoryQuery{Kind: "findings", Limit: 10, ExcludeSelfTests: true}); err != nil {
		t.Fatal(err)
	}
	if seenFilter != "1" {
		t.Fatalf("client dropped filter: %q", seenFilter)
	}
	summary, err := client.Summary(context.Background())
	if err != nil || summary.TotalEvents != 44 || summary.OpenFindings != 11 {
		t.Fatalf("summary client: %+v %v", summary, err)
	}
}
