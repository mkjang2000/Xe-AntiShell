package webpanel

import "testing"

func TestHistoryCredentialFilterSurvivesBrowserProxy(t *testing.T) {
	agent := &operatorAgent{}
	server := testServer(t, agent)
	response := operatorRequest(t, server, "/api/history?kind=events&event_type=process.credential_change&service=worker.service&q=needle&cursor=scoped-page&limit=7", true)
	if response.Code != 200 || agent.query.EventType != "process.credential_change" || agent.query.Service != "worker.service" || agent.query.Search != "needle" || agent.query.Cursor != "scoped-page" || agent.query.Limit != 7 {
		t.Fatalf("proxy lost combined filters: %d %+v", response.Code, agent.query)
	}
}
