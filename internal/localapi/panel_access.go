package localapi

import (
	"context"
	"errors"
	"net/http"

	"xe-antishell/internal/model"
)

type panelAccessBackend interface {
	PanelAccess(context.Context) (model.PanelAccess, error)
}

func (s *Server) handlePanelAccess(w http.ResponseWriter, r *http.Request) {
	backend, ok := s.backend.(panelAccessBackend)
	if !ok {
		http.Error(w, "panel access state unavailable", http.StatusNotImplemented)
		return
	}
	value, err := backend.PanelAccess(r.Context())
	if err == nil && !value.Valid() {
		err = errors.New("invalid panel access state")
	}
	s.writeResult(w, value, err)
}

func (c *Client) PanelAccess(ctx context.Context) (model.PanelAccess, error) {
	var value model.PanelAccess
	if err := c.get(ctx, "/v1/panel-access", &value); err != nil {
		var status *localAPIStatusError
		if errors.As(err, &status) && status.code == http.StatusNotFound && !c.panelAccessSupported.Load() {
			// An older daemon does not expose this endpoint. Keep its local
			// behavior until this client has seen the new access contract.
			return model.PanelAccess{Access: "allow"}, nil
		}
		return model.PanelAccess{}, err
	}
	if !value.Valid() {
		return model.PanelAccess{}, errors.New("invalid panel access state")
	}
	c.panelAccessSupported.Store(true)
	return value, nil
}
