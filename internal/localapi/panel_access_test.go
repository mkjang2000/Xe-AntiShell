package localapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"xe-antishell/internal/model"
)

type panelAccessFixture struct {
	fakeBackend
	access model.PanelAccess
}

func (f *panelAccessFixture) PanelAccess(context.Context) (model.PanelAccess, error) {
	return f.access, nil
}

func TestPanelAccessClientDistinguishesOldDaemonAndFailures(t *testing.T) {
	fixture := &panelAccessFixture{access: model.PanelAccess{Access: "block", Generation: "3"}}
	daemon := NewServer(fixture, 10, 10, 1024)
	var handler http.Handler = http.NotFoundHandler()
	client := &Client{http: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/v1/panel-access" || r.Method != http.MethodGet {
			t.Fatalf("wrong panel access lookup: %s %s", r.Method, r.URL)
		}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, r)
		return recorder.Result(), nil
	})}}

	ctx := context.Background()
	value, err := client.PanelAccess(ctx)
	if err != nil || value != (model.PanelAccess{Access: "allow"}) {
		t.Fatalf("old daemon decision = %+v, %v", value, err)
	}
	// A failing new endpoint must not be treated as an old daemon.
	fixture.access = model.PanelAccess{}
	handler = daemon.httpServer.Handler
	if _, err := client.PanelAccess(ctx); err == nil {
		t.Fatal("invalid response was accepted")
	}
	fixture.access = model.PanelAccess{Access: "block", Generation: "3"}
	value, err = client.PanelAccess(ctx)
	if err != nil || value != fixture.access {
		t.Fatalf("daemon decision = %+v, %v want %+v", value, err, fixture.access)
	}
	handler = http.NotFoundHandler()
	if _, err := client.PanelAccess(ctx); err == nil {
		t.Fatal("disappearing supported route allowed access")
	}
}
