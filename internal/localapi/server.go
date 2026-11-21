// Package localapi exposes the daemon's read-mostly API over a Unix socket.
package localapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"xe-antishell/internal/collector"
	"xe-antishell/internal/model"
)

type Backend interface {
	Status(context.Context) (model.AgentStatus, error)
	Capabilities(context.Context) (model.CapabilityReport, error)
	RefreshCapabilities(context.Context) (model.CapabilityReport, error)
	ListEvents(context.Context, int) ([]model.Event, error)
	ListFindings(context.Context, int) ([]model.Finding, error)
	ProcessTree(context.Context, int, int) ([]model.Process, error)
	SubmitAuditLine(context.Context, []byte) error
}

type Server struct {
	backend      Backend
	maxQuery     int
	defaultQuery int
	maxBodyBytes int64
	httpServer   *http.Server
}

func NewServer(backend Backend, defaultQuery, maxQuery, maxBodyBytes int) *Server {
	if maxQuery < 1 {
		maxQuery = 1000
	}
	if maxBodyBytes < 1024 {
		maxBodyBytes = 1 << 20
	}
	if defaultQuery < 1 {
		defaultQuery = 100
	}
	if maxQuery < defaultQuery {
		defaultQuery = maxQuery
	}
	server := &Server{backend: backend, maxQuery: maxQuery, defaultQuery: defaultQuery, maxBodyBytes: int64(maxBodyBytes)}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", server.handleStatus)
	mux.HandleFunc("GET /v1/panel-access", server.handlePanelAccess)
	mux.HandleFunc("GET /v1/capabilities", server.handleCapabilities)
	mux.HandleFunc("POST /v1/capabilities/refresh", server.handleRefreshCapabilities)
	mux.HandleFunc("GET /v1/events", server.handleEvents)
	mux.HandleFunc("GET /v1/findings", server.handleFindings)
	mux.HandleFunc("GET /v1/history", server.handleHistory)
	mux.HandleFunc("GET /v1/services", server.handleServices)
	mux.HandleFunc("GET /v1/summary", server.handleSummary)
	mux.HandleFunc("GET /v1/rules", server.handleRules)
	mux.HandleFunc("GET /v1/observations", server.handleObservations)
	mux.HandleFunc("GET /v1/resources", server.handleResources)
	mux.HandleFunc("GET /v1/managed/status", server.handleManagedStatus)
	mux.HandleFunc("POST /v1/managed/{action}", server.handleManagement)
	mux.HandleFunc("GET /v1/process-tree", server.handleProcessTree)
	mux.HandleFunc("POST /v1/ingest/audit", server.handleAudit)
	server.httpServer = &http.Server{
		Handler:           mux,
		ConnContext:       unixPeerContext,
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	return server
}

func (s *Server) Serve(listener net.Listener) error {
	err := s.httpServer.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

func ListenUnix(path string, mode os.FileMode) (net.Listener, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("local API socket path must be absolute")
	}
	if filepath.Clean(path) == string(filepath.Separator) {
		return nil, errors.New("local API socket path must not be the filesystem root")
	}
	if mode.Perm()&0o007 != 0 {
		return nil, errors.New("local API socket must not grant permissions to other users")
	}
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0o750); err != nil {
		return nil, fmt.Errorf("create socket directory: %w", err)
	}
	parentInfo, err := os.Lstat(parent)
	if err != nil {
		return nil, fmt.Errorf("inspect socket directory: %w", err)
	}
	if parentInfo.Mode()&os.ModeSymlink != 0 || !parentInfo.IsDir() {
		return nil, fmt.Errorf("socket parent %q must be a real directory", parent)
	}
	if parentInfo.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("socket parent %q must not be group- or world-writable", parent)
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("refusing to replace non-socket path %q", path)
		}
		connection, dialErr := net.DialTimeout("unix", path, 200*time.Millisecond)
		if dialErr == nil {
			_ = connection.Close()
			return nil, fmt.Errorf("refusing to replace active socket %q", path)
		}
		if !errors.Is(dialErr, syscall.ECONNREFUSED) && !errors.Is(dialErr, os.ErrNotExist) {
			return nil, fmt.Errorf("verify stale socket %q: %w", path, dialErr)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("remove stale socket: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect socket path: %w", err)
	}

	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen on Unix socket: %w", err)
	}
	if err := os.Chmod(path, mode); err != nil {
		_ = listener.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("set socket permissions: %w", err)
	}
	return listener, nil
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	value, err := s.backend.Status(r.Context())
	s.writeResult(w, value, err)
}

func (s *Server) handleCapabilities(w http.ResponseWriter, r *http.Request) {
	value, err := s.backend.Capabilities(r.Context())
	s.writeResult(w, value, err)
}

func (s *Server) handleRefreshCapabilities(w http.ResponseWriter, r *http.Request) {
	value, err := s.backend.RefreshCapabilities(r.Context())
	s.writeResult(w, value, err)
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	limit, err := s.queryLimit(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	value, err := s.backend.ListEvents(r.Context(), limit)
	s.writeResult(w, value, err)
}

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	limit, err := s.queryLimit(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	value, err := s.backend.ListFindings(r.Context(), limit)
	s.writeResult(w, value, err)
}

func (s *Server) handleProcessTree(w http.ResponseWriter, r *http.Request) {
	pid, err := strconv.Atoi(r.URL.Query().Get("pid"))
	if err != nil || pid < 1 {
		writeError(w, http.StatusBadRequest, errors.New("pid must be a positive integer"))
		return
	}
	depth := 64
	if raw := r.URL.Query().Get("depth"); raw != "" {
		depth, err = strconv.Atoi(raw)
		if err != nil || depth < 1 || depth > 256 {
			writeError(w, http.StatusBadRequest, errors.New("depth must be between 1 and 256"))
			return
		}
	}
	value, err := s.backend.ProcessTree(r.Context(), pid, depth)
	s.writeResult(w, value, err)
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, s.maxBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			writeError(w, http.StatusRequestEntityTooLarge, fmt.Errorf("read audit record: %w", err))
			return
		}
		writeError(w, http.StatusBadRequest, fmt.Errorf("read audit record: %w", err))
		return
	}
	if len(body) == 0 {
		writeError(w, http.StatusBadRequest, errors.New("empty audit record"))
		return
	}
	if err := s.backend.SubmitAuditLine(r.Context(), body); err != nil {
		if errors.Is(err, collector.ErrInvalidAuditRecord) {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeError(w, http.StatusServiceUnavailable, err)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) queryLimit(r *http.Request) (int, error) {
	value := r.URL.Query().Get("limit")
	if value == "" {
		return s.defaultQuery, nil
	}
	limit, err := strconv.Atoi(value)
	if err != nil || limit < 1 || limit > s.maxQuery {
		return 0, fmt.Errorf("limit must be between 1 and %d", s.maxQuery)
	}
	return limit, nil
}

func (s *Server) writeResult(w http.ResponseWriter, value any, err error) {
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}
