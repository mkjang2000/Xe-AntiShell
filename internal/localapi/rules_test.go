package localapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"xe-antishell/internal/model"
)

type testRulesBackend struct{ *fakeBackend }

func (b testRulesBackend) Rules(context.Context) (model.RuleCatalog, error) {
	return model.RuleCatalog{PolicySource: "managed", ServiceObservationSource: "local", PolicyRevision: 42, Rules: []model.RuleStatus{{ID: "rule-id", RequiredFields: []string{"process.exe"}, Enabled: true}}}, nil
}

func TestRulesReadOnlyClientAndOlderBackend(t *testing.T) {
	server := NewServer(testRulesBackend{&fakeBackend{}}, 100, 1000, 1<<20)
	client := &Client{http: &http.Client{Transport: operatorTransport(func(r *http.Request) (*http.Response, error) {
		recorder := httptest.NewRecorder()
		server.httpServer.Handler.ServeHTTP(recorder, r)
		return recorder.Result(), nil
	})}}
	result, err := client.Rules(context.Background())
	if err != nil || result.PolicyRevision != 42 || result.ServiceObservationSource != "local" || len(result.Rules) != 1 || !result.Rules[0].Enabled || result.Rules[0].RequiredFields[0] != "process.exe" {
		t.Fatalf("rules round trip %+v %v", result, err)
	}
	rec := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/rules", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("unexpected write status %d", rec.Code)
	}
	server = NewServer(&fakeBackend{}, 100, 1000, 1<<20)
	rec = httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/rules", nil))
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("old backend reported %d", rec.Code)
	}
}
