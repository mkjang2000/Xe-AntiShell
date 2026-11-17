package localapi

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

type managedBackendProbe struct {
	fakeBackend
	calls  int
	action string
	body   json.RawMessage
	secret string
}

func (b *managedBackendProbe) ManagementAction(_ context.Context, action string, body json.RawMessage) (any, error) {
	b.calls++
	b.action = action
	b.body = append(json.RawMessage(nil), body...)
	if action == "status" {
		return map[string]any{"enrolled": true, "agent_id": "agent-test", "policy": map[string]any{"active_revision": 3}}, nil
	}
	return map[string]string{"recovery_code": b.secret}, nil
}

func TestManagementRequiresAuthenticatedRootUnixPeer(t *testing.T) {
	for _, test := range []struct {
		name string
		uid  any
	}{
		{name: "missing credentials"},
		{name: "nonroot Unix peer", uid: int64(1000)},
		{name: "unknown peer", uid: int64(-1)},
		{name: "wrong credential type", uid: int(0)},
	} {
		t.Run(test.name, func(t *testing.T) {
			backend := &managedBackendProbe{secret: "private-recovery-code"}
			server := NewServer(backend, 100, 1000, 4096)
			request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/v1/managed/enroll", strings.NewReader(`{"token":"secret-enrollment-token"}`))
			request.Header.Set("X-Peer-UID", "0")
			request.Header.Set("X-Forwarded-For", "127.0.0.1")
			if test.uid != nil {
				request = request.WithContext(context.WithValue(request.Context(), peerUIDKey{}, test.uid))
			}
			response := httptest.NewRecorder()
			server.httpServer.Handler.ServeHTTP(response, request)
			if response.Code != http.StatusForbidden || backend.calls != 0 {
				t.Fatalf("unauthenticated management reached backend: status=%d calls=%d", response.Code, backend.calls)
			}
			if strings.Contains(response.Body.String(), "secret") {
				t.Fatal("denied management echoed secret input")
			}
		})
	}
}

func TestManagementAllowsRootAndRejectsBrowserOrigin(t *testing.T) {
	for _, origin := range []string{"", "http://localhost", "null", "https://example.invalid"} {
		t.Run("origin="+origin, func(t *testing.T) {
			backend := &managedBackendProbe{secret: "private-recovery-code"}
			server := NewServer(backend, 100, 1000, 4096)
			body := `{"operation_id":"prepared-operation"}`
			request := httptest.NewRequest(http.MethodPost, "/v1/managed/authorize", strings.NewReader(body))
			request = request.WithContext(context.WithValue(request.Context(), peerUIDKey{}, int64(0)))
			if origin != "" {
				request.Header.Set("Origin", origin)
			}
			response := httptest.NewRecorder()
			server.httpServer.Handler.ServeHTTP(response, request)
			if origin != "" {
				if response.Code != http.StatusForbidden || backend.calls != 0 {
					t.Fatalf("browser management accepted: status=%d calls=%d", response.Code, backend.calls)
				}
				return
			}
			if response.Code != http.StatusOK || backend.calls != 1 || backend.action != "authorize" || string(backend.body) != body {
				t.Fatalf("root request not delivered intact: status=%d calls=%d action=%q body=%s", response.Code, backend.calls, backend.action, backend.body)
			}
		})
	}
}

func TestManagedReadStatusDoesNotInvokeSecretManagementActions(t *testing.T) {
	backend := &managedBackendProbe{secret: "private-recovery-code"}
	server := NewServer(backend, 100, 1000, 4096)
	request := httptest.NewRequest(http.MethodGet, "/v1/managed/status", nil)
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || backend.calls != 1 || backend.action != "status" || len(backend.body) != 0 {
		t.Fatalf("status invoked management mutation: status=%d action=%q", response.Code, backend.action)
	}
	if !strings.Contains(response.Body.String(), `"active_revision":3`) {
		t.Fatalf("missing monitoring state: %s", response.Body.String())
	}
	for _, secret := range []string{backend.secret, "recovery_code", "key_pem", "certificate_pem", "token"} {
		if strings.Contains(response.Body.String(), secret) {
			t.Fatalf("monitoring response disclosed %q", secret)
		}
	}
}

func TestManagementRejectsOversizedInputBeforeBackend(t *testing.T) {
	backend := &managedBackendProbe{}
	server := NewServer(backend, 100, 1000, 4096)
	request := httptest.NewRequest(http.MethodPost, "/v1/managed/enroll", strings.NewReader(strings.Repeat("x", (128<<10)+1)))
	request = request.WithContext(context.WithValue(request.Context(), peerUIDKey{}, int64(0)))
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || backend.calls != 0 {
		t.Fatalf("oversized input reached backend: status=%d calls=%d", response.Code, backend.calls)
	}
}

func TestPeerContextRejectsNonUnixConnections(t *testing.T) {
	first, second := net.Pipe()
	defer first.Close()
	defer second.Close()
	ctx := unixPeerContext(context.WithValue(context.Background(), peerUIDKey{}, int64(0)), first)
	if uid, ok := ctx.Value(peerUIDKey{}).(int64); !ok || uid != -1 {
		t.Fatalf("non-Unix connection received credentials: %#v", ctx.Value(peerUIDKey{}))
	}
	backend := &managedBackendProbe{}
	server := NewServer(backend, 100, 1000, 4096)
	request := httptest.NewRequest(http.MethodPost, "/v1/managed/challenge", strings.NewReader(`{}`)).WithContext(ctx)
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || backend.calls != 0 {
		t.Fatalf("non-Unix peer accepted: status=%d calls=%d", response.Code, backend.calls)
	}
}

func TestPeerContextUsesKernelUnixCredentials(t *testing.T) {
	files, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	firstFile := os.NewFile(uintptr(files[0]), "test-peer-first")
	secondFile := os.NewFile(uintptr(files[1]), "test-peer-second")
	defer secondFile.Close()
	if _, err := unix.GetsockoptUcred(files[0], unix.SOL_SOCKET, unix.SO_PEERCRED); errors.Is(err, unix.EPERM) {
		firstFile.Close()
		t.Skip("sandbox does not permit Unix peer credentials")
	} else if err != nil {
		firstFile.Close()
		t.Fatal(err)
	}
	first, err := net.FileConn(firstFile)
	firstFile.Close()
	if err != nil {
		if errors.Is(err, unix.EPERM) {
			t.Skip("sandbox does not permit Unix socket inspection")
		}
		t.Fatal(err)
	}
	defer first.Close()
	ctx := unixPeerContext(context.Background(), first)
	if uid, ok := ctx.Value(peerUIDKey{}).(int64); !ok || uid != int64(os.Geteuid()) {
		t.Fatalf("Unix peer UID=%#v, want %d", ctx.Value(peerUIDKey{}), os.Geteuid())
	}
	backend := &managedBackendProbe{}
	server := NewServer(backend, 100, 1000, 4096)
	request := httptest.NewRequest(http.MethodPost, "/v1/managed/challenge", strings.NewReader(`{}`)).WithContext(ctx)
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, request)
	expected, calls := http.StatusForbidden, 0
	if os.Geteuid() == 0 {
		expected, calls = http.StatusOK, 1
	}
	if response.Code != expected || backend.calls != calls {
		t.Fatalf("kernel peer authorization differs from UID: status=%d calls=%d uid=%d", response.Code, backend.calls, os.Geteuid())
	}
}
