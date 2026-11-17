package updates

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

// Recover reports prior work even when opt-out or a package/running-version
// mismatch now prevents a new update. It never installs or restarts a package.
func (m *Manager) Recover(ctx context.Context, client Client, identity Identity, inventory managed.UpdateInventory) error {
	if _, err := os.Lstat(filepath.Join(m.Store.Directory, "job.json")); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	job, err := m.Store.Read()
	if err != nil || job == nil {
		return err
	}
	if job.Plan.Plan.AgentID != identity.AgentID || job.Plan.Plan.EnrollmentID != identity.EnrollmentID {
		apply, err := m.Store.lock(".apply.lock")
		if err != nil {
			return err
		}
		defer unlock(apply)
		return m.Store.archive(job.Plan.Plan.JobID)
	}
	if err := m.Flush(ctx, client, identity); err != nil {
		return err
	}
	if job.Terminal() {
		return nil
	}
	if job.Last().State == "installing" {
		if err := m.Reconcile(ctx, job, inventory.RunningVersion); err != nil {
			return err
		}
		return m.Flush(ctx, client, identity)
	}
	if !inventory.Enabled || !inventory.Supported {
		apply, err := m.Store.lock(".apply.lock")
		if errors.Is(err, ErrBusy) {
			return nil
		}
		if err != nil {
			return err
		}
		defer unlock(apply)
		current, err := m.Store.Read()
		if err != nil || current == nil {
			return err
		}
		if current.Plan.Plan.JobID != job.Plan.Plan.JobID || current.Terminal() {
			return nil
		}
		if current.Last().State == "installing" {
			if err := m.reconcile(ctx, current, inventory.RunningVersion); err != nil {
				return err
			}
			return m.Flush(ctx, client, identity)
		}
		code := inventory.ReasonCode
		if !inventory.Enabled {
			code = "disabled"
		}
		if !managed.ValidUpdateCode(code) || code == "" {
			code = "unsupported_platform"
		}
		if err := m.transition(job.Plan.Plan.JobID, "failed", code, inventory.RunningVersion, inventory.InstalledPackage); err != nil {
			return err
		}
		return m.Flush(ctx, client, identity)
	}
	return nil
}

// A new enrollment cannot deliver an old enrollment's queue. Keep one bounded
// root-only orphan journal for diagnosis and allow the new identity to proceed.
func (s *Store) archive(jobID string) error {
	lock, err := s.lock(".state.lock")
	if err != nil {
		return err
	}
	defer unlock(lock)
	job, err := s.read()
	if err != nil || job == nil {
		return err
	}
	if job.Plan.Plan.JobID != jobID {
		return errors.New("stale_job")
	}
	if !job.Terminal() {
		job.Append("failed", "target_mismatch", "unknown", nil, time.Now().UTC())
	}
	job.Acknowledged = uint64(len(job.Reports))
	if err := s.save(job); err != nil {
		return err
	}
	if err := os.Rename(filepath.Join(s.Directory, "job.json"), filepath.Join(s.Directory, "orphaned-job.json")); err != nil {
		return errors.New("state_unavailable")
	}
	return s.syncDirectory()
}
