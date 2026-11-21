package webpanel

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"xe-antishell/internal/model"
)

type panelDecisionAgent struct {
	fakeAgent
	current atomic.Pointer[model.PanelAccess]
	status  func(context.Context) (model.AgentStatus, error)
}

func (a *panelDecisionAgent) PanelAccess(context.Context) (model.PanelAccess, error) {
	if value := a.current.Load(); value != nil {
		return *value, nil
	}
	return model.PanelAccess{}, errors.New("fixture policy unavailable")
}

func (a *panelDecisionAgent) Status(ctx context.Context) (model.AgentStatus, error) {
	if a.status != nil {
		return a.status(ctx)
	}
	return a.fakeAgent.Status(ctx)
}

func panelRequest(t *testing.T, s *Server, method, path string, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"username": {"admin"}, "password": {"correct-horse-battery-staple1!"}}
	request := httptest.NewRequest(method, path, strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cookie != nil {
		request.AddCookie(cookie)
	}
	recorder := httptest.NewRecorder()
	s.Handler().ServeHTTP(recorder, request)
	return recorder
}

func TestPanelDecisionGatesEveryRouteAndRevokesOldCookies(t *testing.T) {
	agent := &panelDecisionAgent{}
	agent.current.Store(&model.PanelAccess{Access: "allow", Generation: "1"})
	s := testServer(t, agent)
	login := panelRequest(t, s, http.MethodPost, "/login", nil)
	if login.Code != http.StatusSeeOther || len(login.Result().Cookies()) != 1 {
		t.Fatalf("login: %d, %s", login.Code, login.Body.String())
	}
	old := login.Result().Cookies()[0]
	if current := panelRequest(t, s, http.MethodGet, "/api/overview", old); current.Code != http.StatusOK {
		t.Fatalf("authenticated request: %d", current.Code)
	}

	agent.current.Store(&model.PanelAccess{Access: "block", Generation: "2"})
	for _, route := range []struct{ method, path string }{
		{http.MethodGet, "/"}, {http.MethodGet, "/login"}, {http.MethodPost, "/login"},
		{http.MethodPost, "/logout"}, {http.MethodGet, "/api/overview"},
		{http.MethodGet, "/assets/app.css"}, {http.MethodHead, "/assets/rule-definitions.js"},
		{http.MethodPut, "/outside-routing-table"},
	} {
		response := panelRequest(t, s, route.method, route.path, old)
		if response.Code != http.StatusForbidden || response.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s %s while blocked: %d, %v", route.method, route.path, response.Code, response.Header())
		}
	}

	agent.current.Store(&model.PanelAccess{Access: "allow", Generation: "3"})
	restarted, err := NewServer(s.credentials, agent, s.logger)
	if err != nil {
		t.Fatal(err)
	}
	restarted.now = s.now
	denied := panelRequest(t, restarted, http.MethodGet, "/api/overview", old)
	if denied.Code != http.StatusUnauthorized {
		t.Fatalf("old session accepted after reallow and server restart: %d", denied.Code)
	}
	login = panelRequest(t, restarted, http.MethodPost, "/login", nil)
	if login.Code != http.StatusSeeOther || len(login.Result().Cookies()) != 1 {
		t.Fatalf("fresh login: %d", login.Code)
	}
	agent.current.Store(&model.PanelAccess{Access: "allow", Generation: "3"})
	if fresh := panelRequest(t, restarted, http.MethodGet, "/api/overview", login.Result().Cookies()[0]); fresh.Code != http.StatusOK {
		t.Fatalf("unchanged generation invalidated session: %d", fresh.Code)
	}
	agent.current.Store(nil)
	if unavailable := panelRequest(t, restarted, http.MethodGet, "/login", nil); unavailable.Code != http.StatusForbidden {
		t.Fatalf("failed access lookup allowed login: %d", unavailable.Code)
	}
}

func TestPanelDecisionChangeCancelsActiveQuery(t *testing.T) {
	entered := make(chan struct{})
	agent := &panelDecisionAgent{
		status: func(ctx context.Context) (model.AgentStatus, error) {
			close(entered)
			<-ctx.Done()
			return model.AgentStatus{}, ctx.Err()
		},
	}
	agent.current.Store(&model.PanelAccess{Access: "allow", Generation: "1"})
	s := testServer(t, agent)
	token, err := s.credentials.newPanelSession(s.now(), time.Hour, "1")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	request := httptest.NewRequest(http.MethodGet, "/api/overview", nil).WithContext(ctx)
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	recorder := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		s.Handler().ServeHTTP(recorder, request)
		close(done)
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("query did not start")
	}
	agent.current.Store(&model.PanelAccess{Access: "block", Generation: "2"})
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("query was not cancelled")
	}
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("response escaped while access changed: %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestPanelDecisionIsRecheckedBeforeResponseCommit(t *testing.T) {
	agent := &panelDecisionAgent{}
	agent.current.Store(&model.PanelAccess{Access: "allow", Generation: "1"})
	s := testServer(t, agent)
	handler := s.securityHeaders(s.requirePanelAccess(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Set-Cookie", "should-not-escape")
		w.WriteHeader(http.StatusOK)
		agent.current.Store(&model.PanelAccess{Access: "allow", Generation: "3"})
		_, _ = w.Write([]byte("protected response"))
	})))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/login", nil))
	if recorder.Code != http.StatusForbidden || strings.Contains(recorder.Body.String(), "protected response") ||
		recorder.Header().Get("Set-Cookie") != "" || recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("denied response = %d %v %s", recorder.Code, recorder.Header(), recorder.Body.String())
	}
}
