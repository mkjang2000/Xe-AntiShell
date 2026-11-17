package webpanel

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"xe-antishell/internal/model"
)

type operatorAgent struct {
	fakeAgent
	summary    model.OperatorSummary
	errSummary error
	query      model.HistoryQuery
	calls      int
}

func (a *operatorAgent) Summary(context.Context) (model.OperatorSummary, error) {
	a.calls++
	return a.summary, a.errSummary
}
func (a *operatorAgent) History(_ context.Context, q model.HistoryQuery) (model.HistoryPage, error) {
	a.query = q
	return model.HistoryPage{Items: json.RawMessage("[]")}, nil
}
func (a *operatorAgent) Services(context.Context) ([]model.ServiceSummary, error) {
	return []model.ServiceSummary{}, nil
}

func operatorRequest(t *testing.T, server *Server, path string, authenticated bool) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, path, nil)
	if authenticated {
		token, err := server.credentials.NewSession(server.now(), sessionLifetime)
		if err != nil {
			t.Fatal(err)
		}
		request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}

func TestOperatorSummaryRequiresSessionAndPreservesUnavailableState(t *testing.T) {
	agent := &operatorAgent{summary: model.OperatorSummary{TotalEvents: 333, OpenFindings: 22, RecentFindings: []model.Finding{}}}
	server := testServer(t, agent)
	response := operatorRequest(t, server, "/api/summary", false)
	if response.Code != 401 || agent.calls != 0 {
		t.Fatalf("unprotected summary: %d calls=%d", response.Code, agent.calls)
	}
	response = operatorRequest(t, server, "/api/summary", true)
	var summary model.OperatorSummary
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &summary) != nil || summary.TotalEvents != 333 || summary.OpenFindings != 22 {
		t.Fatalf("summary: %d %s", response.Code, response.Body.String())
	}
	response = operatorRequest(t, server, "/api/overview", true)
	var overview overviewResponse
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &overview) != nil || overview.Summary == nil || overview.Summary.OpenFindings != 22 {
		t.Fatalf("overview summary omitted: %d %s", response.Code, response.Body.String())
	}
	agent.errSummary = errors.New("database unavailable")
	response = operatorRequest(t, server, "/api/summary", true)
	if response.Code != http.StatusBadGateway {
		t.Fatalf("summary failure became zero stats: %d %s", response.Code, response.Body.String())
	}
	response = operatorRequest(t, server, "/api/overview", true)
	if response.Code != 200 {
		t.Fatalf("optional summary failure hid live status: %d", response.Code)
	}
	var raw map[string]json.RawMessage
	if json.Unmarshal(response.Body.Bytes(), &raw) != nil {
		t.Fatal("invalid overview JSON")
	}
	if _, exists := raw["summary"]; exists {
		t.Fatalf("unavailable summary must be omitted: %s", response.Body.String())
	}
}

func TestOperatorHistoryForwardsSelfTestFilter(t *testing.T) {
	agent := &operatorAgent{}
	server := testServer(t, agent)
	response := operatorRequest(t, server, "/api/history?kind=findings&exclude_self_tests=1", true)
	if response.Code != 200 || !agent.query.ExcludeSelfTests {
		t.Fatalf("filter omitted: %d %+v", response.Code, agent.query)
	}
	response = operatorRequest(t, server, "/api/history?kind=findings&exclude_self_tests=invalid", true)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("invalid filter accepted: %d", response.Code)
	}
}
