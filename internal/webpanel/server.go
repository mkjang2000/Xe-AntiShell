package webpanel

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"xe-antishell/internal/hostmetrics"
	"xe-antishell/internal/model"
)

const (
	sessionCookieName = "xeas_session"
	sessionLifetime   = 8 * time.Hour
	requestTimeout    = 10 * time.Second
)

//go:embed assets/*
var assets embed.FS

type AgentClient interface {
	Status(context.Context) (model.AgentStatus, error)
	Capabilities(context.Context) (model.CapabilityReport, error)
	Events(context.Context, int) ([]model.Event, error)
	Findings(context.Context, int) ([]model.Finding, error)
	ProcessTree(context.Context, int) ([]model.Process, error)
}

type Server struct {
	credentials Credentials
	agent       AgentClient
	logger      *slog.Logger
	now         func() time.Time
	login       *template.Template
	index       []byte
	static      http.Handler
	limiter     *loginLimiter
	loginSlots  chan struct{}
	handler     http.Handler
}

type overviewResponse struct {
	Rules        *model.RuleCatalog     `json:"rules,omitempty"`
	ServerTime   time.Time              `json:"server_time"`
	Status       model.AgentStatus      `json:"status"`
	Capabilities model.CapabilityReport `json:"capabilities"`
	Findings     []model.Finding        `json:"findings"`
	Events       []model.Event          `json:"events"`
	Resources    *hostmetrics.Snapshot  `json:"resources,omitempty"`
	Managed      json.RawMessage        `json:"managed,omitempty"`
	Summary      *model.OperatorSummary `json:"summary,omitempty"`
}

func NewServer(credentials Credentials, agent AgentClient, logger *slog.Logger) (*Server, error) {
	if err := credentials.Validate(); err != nil {
		return nil, err
	}
	if agent == nil {
		return nil, errors.New("agent client is required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	loginData, err := assets.ReadFile("assets/login.html")
	if err != nil {
		return nil, err
	}
	loginTemplate, err := template.New("login").Parse(string(loginData))
	if err != nil {
		return nil, fmt.Errorf("parse login template: %w", err)
	}
	index, err := assets.ReadFile("assets/index.html")
	if err != nil {
		return nil, err
	}
	staticFS, err := fs.Sub(assets, "assets")
	if err != nil {
		return nil, err
	}
	server := &Server{
		credentials: credentials,
		agent:       agent,
		logger:      logger,
		now:         time.Now,
		login:       loginTemplate,
		index:       index,
		static:      http.FileServer(http.FS(staticFS)),
		limiter:     newLoginLimiter(5, 5*time.Minute),
		loginSlots:  make(chan struct{}, 2),
	}
	server.handler = server.routes()
	return server, nil
}

func (s *Server) Handler() http.Handler {
	return s.handler
}

func (s *Server) HTTPServer(address string, allowNonLoopback bool) (*http.Server, net.Listener, error) {
	listener, err := ListenTCP(address, allowNonLoopback)
	if err != nil {
		return nil, nil, err
	}
	server := &http.Server{
		Addr:              address,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 * 1024,
	}
	return server, listener, nil
}

func ListenTCP(address string, allowNonLoopback bool) (net.Listener, error) {
	if err := ValidateListenAddress(address, allowNonLoopback); err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", address, err)
	}
	return listener, nil
}

func ValidateListenAddress(address string, allowNonLoopback bool) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid listen address: %w", err)
	}
	parsed, err := netip.ParseAddr(host)
	if err != nil {
		return errors.New("listen address must use a literal IP")
	}
	if !parsed.IsLoopback() && !allowNonLoopback {
		return errors.New("non-loopback listen address requires explicit permission")
	}
	if !parsed.IsLoopback() && !parsed.IsUnspecified() && !parsed.IsGlobalUnicast() {
		return errors.New("listen address is not a unicast or wildcard IP")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 0 || portNumber > 65535 {
		return errors.New("invalid listen port")
	}
	return nil
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /login", s.loginSubmit)
	mux.Handle("POST /logout", s.authenticated(http.HandlerFunc(s.logout)))
	mux.HandleFunc("GET /assets/rule-definitions.js", serveRuleDefinitions)
	mux.Handle("GET /assets/", http.StripPrefix("/assets", s.static))
	mux.Handle("GET /api/overview", s.authenticatedAPI(http.HandlerFunc(s.overview)))
	mux.Handle("GET /api/process-tree", s.authenticatedAPI(http.HandlerFunc(s.processTree)))
	mux.Handle("GET /api/observations", s.authenticatedAPI(http.HandlerFunc(s.observations)))
	mux.Handle("GET /api/history", s.authenticatedAPI(http.HandlerFunc(s.history)))
	mux.Handle("GET /api/services", s.authenticatedAPI(http.HandlerFunc(s.services)))
	mux.Handle("GET /api/summary", s.authenticatedAPI(http.HandlerFunc(s.summary)))
	mux.Handle("GET /api/resources", s.authenticatedAPI(http.HandlerFunc(s.resources)))
	mux.Handle("GET /", s.authenticated(http.HandlerFunc(s.dashboard)))
	return s.securityHeaders(s.requirePanelAccess(mux))
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) authenticated(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.hasSession(r) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) authenticatedAPI(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.hasSession(r) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) hasSession(r *http.Request) bool {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return false
	}
	_, err = s.credentials.verifyPanelSession(cookie.Value, s.now(), panelSessionGeneration(r))
	return err == nil
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	if s.hasSession(r) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.login.Execute(w, struct{ Error bool }{}); err != nil {
		s.logger.Error("render login page", "error", err)
	}
}

func (s *Server) loginSubmit(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		s.logger.Warn("rejected request origin", "origin", r.Header.Get("Origin"), "host", r.Host)
		http.Error(w, "invalid request origin", http.StatusForbidden)
		return
	}
	select {
	case s.loginSlots <- struct{}{}:
		defer func() { <-s.loginSlots }()
	default:
		http.Error(w, "too many concurrent login attempts", http.StatusTooManyRequests)
		return
	}
	ip := remoteIP(r.RemoteAddr)
	if !s.limiter.Allow(ip, s.now()) {
		http.Error(w, "too many login attempts", http.StatusTooManyRequests)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4*1024)
	if err := r.ParseForm(); err != nil {
		s.renderLoginError(w, http.StatusBadRequest)
		return
	}
	username, password := r.FormValue("username"), r.FormValue("password")
	if !s.credentials.Verify(username, password) {
		s.limiter.Failure(ip, s.now())
		time.Sleep(150 * time.Millisecond)
		s.renderLoginError(w, http.StatusUnauthorized)
		return
	}
	s.limiter.Success(ip)
	token, err := s.credentials.newPanelSession(s.now(), sessionLifetime, panelSessionGeneration(r))
	if err != nil {
		s.logger.Error("create session", "error", err)
		http.Error(w, "login unavailable", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(sessionLifetime.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) renderLoginError(w http.ResponseWriter, status int) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := s.login.Execute(w, struct{ Error bool }{Error: true}); err != nil {
		s.logger.Error("render login error", "error", err)
	}
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		s.logger.Warn("rejected request origin", "origin", r.Header.Get("Origin"), "host", r.Host)
		http.Error(w, "invalid request origin", http.StatusForbidden)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(s.index)
}

func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()
	status, err := s.agent.Status(ctx)
	if err != nil {
		s.upstreamError(w, "status", err)
		return
	}
	capabilities, err := s.agent.Capabilities(ctx)
	if err != nil {
		s.upstreamError(w, "capabilities", err)
		return
	}
	findings, err := s.agent.Findings(ctx, 100)
	if err != nil {
		s.upstreamError(w, "findings", err)
		return
	}
	events, err := s.agent.Events(ctx, 200)
	if err != nil {
		s.upstreamError(w, "events", err)
		return
	}
	response := overviewResponse{ServerTime: s.now().UTC(), Status: status, Capabilities: capabilities, Findings: findings, Events: events}
	if client, ok := s.agent.(summaryClient); ok {
		if summary, err := client.Summary(ctx); err == nil {
			response.Summary = &summary
		} else {
			s.logger.Error("agent API request failed", "operation", "operator summary", "error", err)
		}
	}
	if client, ok := s.agent.(resourceClient); ok {
		if snapshot, err := client.Resources(ctx); err == nil {
			response.Resources = &snapshot
		}
	}
	if client, ok := s.agent.(interface {
		ManagedStatus(context.Context) (json.RawMessage, error)
	}); ok {
		if status, err := client.ManagedStatus(ctx); err == nil {
			response.Managed = status
		}
	}
	if client, ok := s.agent.(interface {
		Rules(context.Context) (model.RuleCatalog, error)
	}); ok {
		if catalog, err := client.Rules(ctx); err == nil {
			response.Rules = &catalog
		}
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) processTree(w http.ResponseWriter, r *http.Request) {
	pid, err := strconv.Atoi(r.URL.Query().Get("pid"))
	if err != nil || pid < 1 || pid > 1<<30 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "valid pid is required"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()
	processes, err := s.agent.ProcessTree(ctx, pid)
	if err != nil {
		s.upstreamError(w, "process tree", err)
		return
	}
	writeJSON(w, http.StatusOK, processes)
}

func (s *Server) upstreamError(w http.ResponseWriter, operation string, err error) {
	s.logger.Error("agent API request failed", "operation", operation, "error", err)
	writeJSON(w, http.StatusBadGateway, map[string]string{"error": "agent data is temporarily unavailable"})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func sameOrigin(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	if origin == "null" {
		requestURL := &url.URL{Host: r.Host}
		return loopbackHost(requestURL.Hostname()) && loopbackHost(remoteIP(r.RemoteAddr))
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.User != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return false
	}
	requestURL := &url.URL{Host: r.Host}
	if !sameOriginHost(parsed.Hostname(), requestURL.Hostname()) {
		return false
	}
	requestScheme := "http"
	if r.TLS != nil {
		requestScheme = "https"
	}
	return parsed.Scheme == requestScheme && effectivePort(parsed.Scheme, parsed.Port()) == effectivePort(requestScheme, requestURL.Port())
}

func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	address, err := netip.ParseAddr(host)
	return err == nil && address.IsLoopback()
}

func sameOriginHost(originHost, requestHost string) bool {
	if loopbackHost(originHost) && loopbackHost(requestHost) {
		return true
	}
	originAddress, originErr := netip.ParseAddr(originHost)
	requestAddress, requestErr := netip.ParseAddr(requestHost)
	if originErr == nil && requestErr == nil {
		return originAddress.Unmap() == requestAddress.Unmap()
	}
	return strings.EqualFold(strings.TrimSuffix(originHost, "."), strings.TrimSuffix(requestHost, "."))
}

func effectivePort(scheme, port string) string {
	if port != "" {
		return port
	}
	if scheme == "https" {
		return "443"
	}
	return "80"
}

func remoteIP(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return address
	}
	return host
}

type loginAttempt struct {
	failures int
	start    time.Time
}

type loginLimiter struct {
	mu       sync.Mutex
	max      int
	window   time.Duration
	attempts map[string]loginAttempt
}

func newLoginLimiter(max int, window time.Duration) *loginLimiter {
	return &loginLimiter{max: max, window: window, attempts: make(map[string]loginAttempt)}
}

func (l *loginLimiter) Allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	attempt, ok := l.attempts[key]
	if !ok || now.Sub(attempt.start) >= l.window {
		delete(l.attempts, key)
		return true
	}
	return attempt.failures < l.max
}

func (l *loginLimiter) Failure(key string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	attempt, ok := l.attempts[key]
	if !ok || now.Sub(attempt.start) >= l.window {
		attempt = loginAttempt{start: now}
	}
	attempt.failures++
	l.attempts[key] = attempt
}

func (l *loginLimiter) Success(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.attempts, key)
}
