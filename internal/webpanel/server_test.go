package webpanel

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"xe-antishell/internal/model"
)

type fakeAgent struct {
	err error
}

func (f fakeAgent) Status(context.Context) (model.AgentStatus, error) {
	return model.AgentStatus{Health: model.HealthHealthy, Mode: model.AgentModeActive}, f.err
}
func (f fakeAgent) Capabilities(context.Context) (model.CapabilityReport, error) {
	return model.CapabilityReport{Capabilities: map[string]model.Capability{}}, f.err
}
func (f fakeAgent) Events(context.Context, int) ([]model.Event, error) { return []model.Event{}, f.err }
func (f fakeAgent) Findings(context.Context, int) ([]model.Finding, error) {
	return []model.Finding{}, f.err
}
func (f fakeAgent) ProcessTree(context.Context, int) ([]model.Process, error) {
	return []model.Process{}, f.err
}

func testServer(t *testing.T, agent AgentClient) *Server {
	t.Helper()
	server, err := NewServer(testCredentials(t), agent, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	server.now = func() time.Time { return time.Unix(1_700_000_000, 0) }
	return server
}

func TestProtectedRoutesAndSecurityHeaders(t *testing.T) {
	server := testServer(t, fakeAgent{})
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/login" {
		t.Fatalf("dashboard response = %d location=%q", response.Code, response.Header().Get("Location"))
	}
	if response.Header().Get("Content-Security-Policy") == "" || response.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatal("security headers are missing")
	}
	request = httptest.NewRequest(http.MethodGet, "/api/overview", nil)
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("API response = %d", response.Code)
	}
	request = httptest.NewRequest(http.MethodGet, "/assets/app.css", nil)
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Header().Get("Content-Type"), "text/css") {
		t.Fatalf("login asset response = %d content-type=%q", response.Code, response.Header().Get("Content-Type"))
	}
}

func TestLoginDashboardAPIAndLogout(t *testing.T) {
	server := testServer(t, fakeAgent{})
	wrong := url.Values{"username": {"admin"}, "password": {"wrong-password-value"}}
	request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(wrong.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.RemoteAddr = "127.0.0.1:1234"
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("wrong login response = %d", response.Code)
	}

	valid := url.Values{"username": {"admin"}, "password": {"correct-horse-battery-staple1!"}}
	request = httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(valid.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.RemoteAddr = "127.0.0.1:1234"
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("valid login response = %d body=%s", response.Code, response.Body.String())
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("session cookie = %#v", cookies)
	}

	request = httptest.NewRequest(http.MethodGet, "/api/overview", nil)
	request.AddCookie(cookies[0])
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"health":"healthy"`) {
		t.Fatalf("overview response = %d body=%s", response.Code, response.Body.String())
	}

	request = httptest.NewRequest(http.MethodPost, "/logout", nil)
	request.AddCookie(cookies[0])
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || response.Result().Cookies()[0].MaxAge != -1 {
		t.Fatalf("logout response = %d cookies=%#v", response.Code, response.Result().Cookies())
	}
}

func TestProcessTreeValidationAndUpstreamError(t *testing.T) {
	server := testServer(t, fakeAgent{err: errors.New("socket details must not leak")})
	token, err := server.credentials.NewSession(server.now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cookie := &http.Cookie{Name: sessionCookieName, Value: token}
	request := httptest.NewRequest(http.MethodGet, "/api/process-tree?pid=bad", nil)
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("bad pid response = %d", response.Code)
	}
	request = httptest.NewRequest(http.MethodGet, "/api/overview", nil)
	request.AddCookie(cookie)
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusBadGateway || strings.Contains(response.Body.String(), "socket details") {
		t.Fatalf("upstream response = %d body=%s", response.Code, response.Body.String())
	}
}

func TestLoginConcurrencyIsBounded(t *testing.T) {
	server := testServer(t, fakeAgent{})
	server.loginSlots <- struct{}{}
	server.loginSlots <- struct{}{}
	defer func() {
		<-server.loginSlots
		<-server.loginSlots
	}()
	form := url.Values{"username": {"admin"}, "password": {"correct-horse-battery-staple1!"}}
	request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.RemoteAddr = "127.0.0.1:1234"
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("concurrent login response = %d", response.Code)
	}
}

func TestSameOriginAcceptsLoopbackAliases(t *testing.T) {
	tests := []struct {
		name   string
		host   string
		origin string
		want   bool
	}{
		{name: "missing origin", host: "127.0.0.1:9088", want: true},
		{name: "exact IPv4", host: "127.0.0.1:9088", origin: "http://127.0.0.1:9088", want: true},
		{name: "localhost alias", host: "127.0.0.1:9088", origin: "http://localhost:9088", want: true},
		{name: "reverse alias", host: "localhost:9088", origin: "http://127.0.0.1:9088", want: true},
		{name: "IPv6 loopback", host: "[::1]:9088", origin: "http://[::1]:9088", want: true},
		{name: "external exact host", host: "192.0.2.10:9088", origin: "http://192.0.2.10:9088", want: true},
		{name: "external DNS host", host: "Monitor.Example:9088", origin: "http://monitor.example:9088", want: true},
		{name: "foreign origin", host: "127.0.0.1:9088", origin: "https://example.com", want: false},
		{name: "foreign host", host: "example.com:9088", origin: "http://127.0.0.1:9088", want: false},
		{name: "wrong port", host: "127.0.0.1:9088", origin: "http://127.0.0.1:9000", want: false},
		{name: "wrong scheme", host: "127.0.0.1:9088", origin: "https://127.0.0.1:9088", want: false},
		{name: "extension scheme", host: "127.0.0.1:9088", origin: "chrome-extension://example", want: false},
		{name: "opaque loopback tunnel", host: "127.0.0.1:9088", origin: "null", want: true},
		{name: "opaque external host", host: "192.0.2.10:9088", origin: "null", want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "http://"+test.host+"/login", nil)
			request.Host = test.host
			request.RemoteAddr = "127.0.0.1:12345"
			if test.origin != "" {
				request.Header.Set("Origin", test.origin)
			}
			if got := sameOrigin(request); got != test.want {
				t.Fatalf("sameOrigin() = %t, want %t", got, test.want)
			}
		})
	}
	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:9088/login", nil)
	request.Host = "127.0.0.1:9088"
	request.RemoteAddr = "192.0.2.20:12345"
	request.Header.Set("Origin", "null")
	if sameOrigin(request) {
		t.Fatal("opaque origin from a non-loopback peer was accepted")
	}
}

func TestValidateListenAddress(t *testing.T) {
	if err := ValidateListenAddress("127.0.0.1:0", false); err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"0.0.0.0:9088", "192.0.2.1:9088"} {
		if err := ValidateListenAddress(address, false); err == nil {
			t.Fatalf("non-loopback address %q was accepted without permission", address)
		}
		if err := ValidateListenAddress(address, true); err != nil {
			t.Fatalf("explicit non-loopback address %q was rejected: %v", address, err)
		}
	}
	if err := ValidateListenAddress("localhost:9088", true); err == nil {
		t.Fatal("non-literal listen address was accepted")
	}
}
