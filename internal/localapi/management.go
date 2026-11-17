package localapi

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"

	"golang.org/x/sys/unix"
)

type peerUIDKey struct{}
type managementBackend interface {
	ManagementAction(context.Context, string, json.RawMessage) (any, error)
}

func unixPeerContext(ctx context.Context, connection net.Conn) context.Context {
	uid := int64(-1)
	if connection, ok := connection.(*net.UnixConn); ok {
		raw, err := connection.SyscallConn()
		if err == nil {
			_ = raw.Control(func(fd uintptr) {
				credentials, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
				if err == nil {
					uid = int64(credentials.Uid)
				}
			})
		}
	}
	return context.WithValue(ctx, peerUIDKey{}, uid)
}
func (s *Server) handleManagedStatus(w http.ResponseWriter, r *http.Request) {
	backend, ok := s.backend.(managementBackend)
	if !ok {
		http.Error(w, "management unavailable", http.StatusNotImplemented)
		return
	}
	value, err := backend.ManagementAction(r.Context(), "status", nil)
	s.writeResult(w, value, err)
}
func (s *Server) handleManagement(w http.ResponseWriter, r *http.Request) {
	uid, ok := r.Context().Value(peerUIDKey{}).(int64)
	if !ok || uid != 0 {
		http.Error(w, "root Unix peer required", http.StatusForbidden)
		return
	}
	if r.Header.Get("Origin") != "" {
		http.Error(w, "browser management requests are not accepted", http.StatusForbidden)
		return
	}
	backend, ok := s.backend.(managementBackend)
	if !ok {
		http.Error(w, "management unavailable", http.StatusNotImplemented)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 128<<10))
	if err != nil {
		http.Error(w, "management input exceeds limit", http.StatusBadRequest)
		return
	}
	value, err := backend.ManagementAction(r.Context(), r.PathValue("action"), body)
	s.writeResult(w, value, err)
}
func (c *Client) Management(ctx context.Context, action string, input, output any) error {
	body, err := json.Marshal(input)
	if err != nil {
		return err
	}
	return c.request(ctx, http.MethodPost, "/v1/managed/"+action, body, output)
}
func (c *Client) ManagedStatus(ctx context.Context) (json.RawMessage, error) {
	var result json.RawMessage
	err := c.get(ctx, "/v1/managed/status", &result)
	return result, err
}
