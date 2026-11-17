package localapi

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"xe-antishell/internal/collector"
	"xe-antishell/internal/model"
)

type fakeBackend struct {
	lastLimit int
	auditErr  error
	auditBody []byte
}

func (b *fakeBackend) Status(context.Context) (model.AgentStatus, error) {
	return model.AgentStatus{}, nil
}
func (b *fakeBackend) Capabilities(context.Context) (model.CapabilityReport, error) {
	return model.CapabilityReport{}, nil
}
func (b *fakeBackend) RefreshCapabilities(context.Context) (model.CapabilityReport, error) {
	return model.CapabilityReport{}, nil
}
func (b *fakeBackend) ListEvents(_ context.Context, limit int) ([]model.Event, error) {
	b.lastLimit = limit
	return []model.Event{}, nil
}
func (b *fakeBackend) ListFindings(_ context.Context, limit int) ([]model.Finding, error) {
	b.lastLimit = limit
	return []model.Finding{}, nil
}
func (b *fakeBackend) ProcessTree(context.Context, int, int) ([]model.Process, error) {
	return []model.Process{}, nil
}
func (b *fakeBackend) SubmitAuditLine(_ context.Context, body []byte) error {
	b.auditBody = append([]byte(nil), body...)
	return b.auditErr
}

func TestListenUnixRefusesActiveSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "api.sock")
	first, err := ListenUnix(path, 0o660)
	if err != nil {
		if errors.Is(err, syscall.EPERM) {
			t.Skip("sandbox does not permit Unix sockets")
		}
		t.Fatal(err)
	}
	defer first.Close()

	if _, err := ListenUnix(path, 0o660); err == nil || !strings.Contains(err.Error(), "active socket") {
		t.Fatalf("expected active socket refusal, got %v", err)
	}
	connection, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatalf("original listener was disrupted: %v", err)
	}
	_ = connection.Close()
}

func TestListenUnixReplacesOnlyStaleSocket(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "api.sock")
	address, err := net.ResolveUnixAddr("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	stale, err := net.ListenUnix("unix", address)
	if err != nil {
		if errors.Is(err, syscall.EPERM) {
			t.Skip("sandbox does not permit Unix sockets")
		}
		t.Fatal(err)
	}
	stale.SetUnlinkOnClose(false)
	if err := stale.Close(); err != nil {
		t.Fatal(err)
	}
	listener, err := ListenUnix(path, 0o660)
	if err != nil {
		t.Fatalf("replace stale socket: %v", err)
	}
	_ = listener.Close()
}

func TestListenUnixRejectsUnsafeTargets(t *testing.T) {
	directory := t.TempDir()
	regular := filepath.Join(directory, "regular")
	if err := os.WriteFile(regular, []byte("do not replace"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ListenUnix(regular, 0o660); err == nil {
		t.Fatal("expected non-socket target refusal")
	}
	if _, err := ListenUnix(filepath.Join(directory, "world.sock"), 0o666); err == nil {
		t.Fatal("expected world-accessible mode refusal")
	}
}

func TestDefaultQueryDoesNotExceedConfiguredMaximum(t *testing.T) {
	backend := &fakeBackend{}
	server := NewServer(backend, 10, 10, 1024)
	request := httptest.NewRequest(http.MethodGet, "/v1/events", nil)
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d", response.Code)
	}
	if backend.lastLimit != 10 {
		t.Fatalf("default query limit = %d, want 10", backend.lastLimit)
	}
}

func TestAuditHandlerClassifiesInputFailures(t *testing.T) {
	t.Run("oversized", func(t *testing.T) {
		backend := &fakeBackend{}
		server := NewServer(backend, 100, 100, 1024)
		request := httptest.NewRequest(http.MethodPost, "/v1/ingest/audit", strings.NewReader(strings.Repeat("x", 1025)))
		response := httptest.NewRecorder()
		server.httpServer.Handler.ServeHTTP(response, request)
		if response.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("status = %d, want %d", response.Code, http.StatusRequestEntityTooLarge)
		}
	})

	t.Run("malformed", func(t *testing.T) {
		backend := &fakeBackend{auditErr: collector.ErrInvalidAuditRecord}
		server := NewServer(backend, 100, 100, 1024)
		request := httptest.NewRequest(http.MethodPost, "/v1/ingest/audit", strings.NewReader("not an audit record"))
		response := httptest.NewRecorder()
		server.httpServer.Handler.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
		}
	})
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func TestStreamAuditUsesBoundedSendTimeout(t *testing.T) {
	client := &Client{http: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		<-request.Context().Done()
		return nil, request.Context().Err()
	})}}
	started := time.Now()
	err := client.StreamAudit(context.Background(), strings.NewReader("audit record\n"), 1024)
	if err == nil || !strings.Contains(err.Error(), "send_failures=1") {
		t.Fatalf("expected aggregated send failure, got %v", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("send timeout was not bounded: %s", elapsed)
	}
}

func TestStreamAuditRecoversAfterSendFailure(t *testing.T) {
	var calls atomic.Int64
	firstAttempt := make(chan struct{})
	var delivered string
	client := &Client{http: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			close(firstAttempt)
			return nil, errors.New("daemon socket unavailable")
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			return nil, err
		}
		delivered = string(body)
		return &http.Response{
			StatusCode: http.StatusAccepted,
			Status:     "202 Accepted",
			Body:       http.NoBody,
			Header:     make(http.Header),
			Request:    request,
		}, nil
	})}}

	reader, writer := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- client.StreamAudit(context.Background(), reader, 1024) }()
	if _, err := io.WriteString(writer, "first record\n"); err != nil {
		t.Fatal(err)
	}
	<-firstAttempt
	// This record arrives while the circuit is open and must be drained
	// without another blocking connection attempt.
	if _, err := io.WriteString(writer, "during backoff\n"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(auditRetryInitial + 50*time.Millisecond)
	if _, err := io.WriteString(writer, "after recovery\n"); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	err := <-done
	if err == nil || !strings.Contains(err.Error(), "send_failures=1") || !strings.Contains(err.Error(), "dropped=1") {
		t.Fatalf("expected the historical gap to be reported, got %v", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("request calls = %d, want 2", calls.Load())
	}
	if delivered != "after recovery" {
		t.Fatalf("recovered payload = %q", delivered)
	}
}

func TestStreamAuditReportsQueueDrops(t *testing.T) {
	var calls atomic.Int64
	client := &Client{http: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			time.Sleep(100 * time.Millisecond)
		}
		return &http.Response{
			StatusCode: http.StatusAccepted,
			Status:     "202 Accepted",
			Body:       http.NoBody,
			Header:     make(http.Header),
			Request:    request,
		}, nil
	})}}
	input := strings.Repeat("type=TEST msg=audit(1.0:1): value=1\n", auditForwardQueueSize*4)
	err := client.StreamAudit(context.Background(), strings.NewReader(input), 1024)
	if err == nil || !strings.Contains(err.Error(), "dropped=") {
		t.Fatalf("expected reported queue drops, got %v", err)
	}
}

func TestStreamAuditValidatesLineLimitBeforeRequest(t *testing.T) {
	client := &Client{http: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("must not be called")
	})}}
	if err := client.StreamAudit(context.Background(), strings.NewReader("record\n"), 0); err == nil {
		t.Fatal("expected invalid maximum line size")
	}
}
