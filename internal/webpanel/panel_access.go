package webpanel

import (
	"context"
	"net/http"
	"strings"
	"time"

	"xe-antishell/internal/model"
)

const (
	panelAccessTimeout = time.Second
	panelAccessWatch   = 250 * time.Millisecond
)

type panelAccessClient interface {
	PanelAccess(context.Context) (model.PanelAccess, error)
}

type panelSessionKey struct{}

func panelSessionGeneration(r *http.Request) string {
	generation, _ := r.Context().Value(panelSessionKey{}).(string)
	return generation
}

func checkPanelAccess(ctx context.Context, client panelAccessClient) (model.PanelAccess, bool) {
	ctx, cancel := context.WithTimeout(ctx, panelAccessTimeout)
	defer cancel()
	value, err := client.PanelAccess(ctx)
	return value, err == nil && ctx.Err() == nil && value.Valid() && value.Access == "allow"
}

func (s *Server) requirePanelAccess(next http.Handler) http.Handler {
	client, ok := s.agent.(panelAccessClient)
	if !ok {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		access, allowed := checkPanelAccess(r.Context(), client)
		if !allowed {
			http.Error(w, "web panel access denied", http.StatusForbidden)
			return
		}

		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()
		ctx = context.WithValue(ctx, panelSessionKey{}, access.Generation)
		writer := &panelAccessWriter{
			ResponseWriter: w,
			baseHeaders:    w.Header().Clone(),
			ctx:            ctx,
			cancel:         cancel,
			client:         client,
			access:         access,
		}
		// Most routes respond immediately. Query handlers may wait on the
		// daemon, so also cancel their context while a policy is changing.
		if strings.HasPrefix(r.URL.Path, "/api/") {
			go watchPanelAccess(ctx, cancel, client, access)
		}
		next.ServeHTTP(writer, r.WithContext(ctx))
		if !writer.committed {
			writer.commit()
		}
	})
}

func watchPanelAccess(ctx context.Context, cancel context.CancelFunc, client panelAccessClient, access model.PanelAccess) {
	ticker := time.NewTicker(panelAccessWatch)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			current, allowed := checkPanelAccess(ctx, client)
			if !allowed || current != access {
				cancel()
				return
			}
		}
	}
}

// Panel handlers do not stream from the agent. Deferring the status until
// the first body write keeps a login cookie or completed query from crossing
// the HTTP boundary after a newer access decision is observed.
type panelAccessWriter struct {
	http.ResponseWriter
	baseHeaders http.Header
	ctx         context.Context
	cancel      context.CancelFunc
	client      panelAccessClient
	access      model.PanelAccess
	status      int
	committed   bool
	denied      bool
}

func (w *panelAccessWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}

func (w *panelAccessWriter) Write(p []byte) (int, error) {
	if !w.commit() {
		return len(p), nil
	}
	return w.ResponseWriter.Write(p)
}

func (w *panelAccessWriter) commit() bool {
	if w.denied {
		return false
	}
	access, allowed := checkPanelAccess(w.ctx, w.client)
	if !allowed || access != w.access {
		w.denied = true
		w.cancel()
		if !w.committed {
			header := w.Header()
			clear(header)
			for name, values := range w.baseHeaders {
				header[name] = values
			}
			http.Error(w.ResponseWriter, "web panel access denied", http.StatusForbidden)
			w.committed = true
		}
		return false
	}
	if !w.committed {
		if w.status == 0 {
			w.status = http.StatusOK
		}
		w.ResponseWriter.WriteHeader(w.status)
		w.committed = true
	}
	return true
}
