package localapi

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"xe-antishell/internal/model"
)

func TestHistoryCredentialFilterSurvivesClientAndLocalRoute(t *testing.T) {
	query := model.HistoryQuery{Kind: "events", EventType: "process.credential_change", Service: "worker.service", Search: "needle", Cursor: "scoped-page", Limit: 7}
	backend := &operatorBackend{fakeBackend: &fakeBackend{}}
	server := NewServer(backend, 100, 1000, 1<<20)
	client := &Client{http: &http.Client{Transport: operatorTransport(func(r *http.Request) (*http.Response, error) {
		recorder := httptest.NewRecorder()
		server.httpServer.Handler.ServeHTTP(recorder, r)
		return &http.Response{StatusCode: recorder.Code, Header: recorder.Header(), Body: io.NopCloser(strings.NewReader(recorder.Body.String()))}, nil
	})}}
	if _, err := client.History(context.Background(), query); err != nil {
		t.Fatal(err)
	}
	if backend.query != query {
		t.Fatalf("client/route lost filters: got=%+v want=%+v", backend.query, query)
	}
}
