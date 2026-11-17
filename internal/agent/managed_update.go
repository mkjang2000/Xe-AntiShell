package agent

import (
	"context"
	"errors"
	"time"

	"xe-antishell/internal/buildinfo"
	"xe-antishell/internal/managedclient"
	"xe-antishell/internal/storage"
	"xe-antishell/internal/updates"
)

func (s *Service) managedUpdateLoop(ctx context.Context) {
	for {
		s.managedUpdateOnce(ctx)
		if !managedWait(ctx, 15*time.Second) {
			return
		}
	}
}

func (s *Service) managedUpdateOnce(ctx context.Context) {
	client, state, err := s.managedConnection(ctx)
	if errors.Is(err, storage.ErrNotFound) {
		return
	}
	if err != nil {
		s.managedError("update", "update identity unavailable")
		return
	}
	standard := updates.StandardPaths(s.config.Agent.SocketPath, s.config.Agent.DatabasePath)
	inventory := updates.Inventory(ctx, s.updateManager.Runner, s.config.Updates.Enabled, standard)
	if err := client.UpdateInventory(ctx, inventory); err != nil {
		if managedclient.UpdateUnsupported(err) {
			s.managedError("update", "")
			return
		}
		s.managedError("update", "central update inventory failed")
		return
	}
	s.managedContact()
	if buildinfo.PackageRelease == "" || !standard {
		s.managedError("update", "")
		return
	}
	identity := updates.Identity{AgentID: state.AgentID, EnrollmentID: state.EnrollmentID, KeyID: state.PolicyKeyID, PublicKey: state.PolicyPublicKey}
	// A second/custom process must not touch the canonical daemon's journal.
	// This also defers startup work until the local root API is available.
	if s.updateManager.CurrentIdentity == nil {
		s.managedError("update", "update identity unavailable")
		return
	}
	current, err := s.updateManager.CurrentIdentity(ctx)
	if err != nil || current != identity {
		s.managedError("update", "update identity unavailable")
		return
	}
	if err := s.updateManager.Once(ctx, client, identity, inventory); err != nil {
		if managedclient.UpdateUnsupported(err) || errors.Is(err, updates.ErrBusy) {
			s.managedError("update", "")
			return
		}
		s.managedError("update", "central update operation pending; local journal retained")
		return
	}
	s.managedError("update", "")
}
