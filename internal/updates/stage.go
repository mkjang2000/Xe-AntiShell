package updates

import (
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

type Identity struct {
	AgentID      string `json:"agent_id"`
	EnrollmentID string `json:"enrollment_id"`
	KeyID        string `json:"key_id"`
	PublicKey    string `json:"public_key"`
}

func (i Identity) Keys() (map[string]ed25519.PublicKey, error) {
	key, err := managed.DecodePublicKey(i.PublicKey)
	return map[string]ed25519.PublicKey{i.KeyID: key}, err
}

type Client interface {
	DesiredUpdate(context.Context) (*managed.SignedUpdatePlan, error)
	DownloadUpdateArtifact(context.Context, managed.UpdateRelease, io.Writer) error
	ClaimUpdate(context.Context, managed.UpdateClaim) (managed.SignedUpdateAuthorization, error)
	ReportUpdate(context.Context, managed.UpdateReport) error
}

type Manager struct {
	Store           *Store
	Runner          Runner
	Now             func() time.Time
	Healthy         func(context.Context, managed.UpdatePlan) bool
	CheckLocal      func(context.Context, managed.UpdatePlan) error
	CurrentIdentity func(context.Context) (Identity, error)
	Platform        func() (string, string, string)
	HealthTimeout   time.Duration
	RunningVersion  func(context.Context) string
	// Tests may inject independent public anchors. Production constructors use
	// only the built-in keyring; job/config/network input cannot select it.
	PublisherKeys     map[string]ed25519.PublicKey
	CaptureCollection func(context.Context) (CollectionBaseline, error)
	VerifyCollection  func(context.Context, CollectionBaseline) bool
}

func (m *Manager) publisherKeys() map[string]ed25519.PublicKey {
	if m.PublisherKeys != nil {
		return m.PublisherKeys
	}
	return managed.BuiltinReleasePublisherKeys()
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now().UTC()
	}
	return time.Now().UTC()
}

func (m *Manager) Flush(ctx context.Context, client Client, identity Identity) error {
	for {
		job, err := m.Store.Read()
		if err != nil || job == nil {
			return err
		}
		if job.Plan.Plan.AgentID != identity.AgentID || job.Plan.Plan.EnrollmentID != identity.EnrollmentID || job.Acknowledged == uint64(len(job.Reports)) {
			return nil
		}
		report := job.Reports[job.Acknowledged]
		if err := client.ReportUpdate(ctx, report); err != nil {
			return err
		}
		if err := m.Store.Change(func(current *Job) (*Job, error) {
			if current == nil || current.Plan.Plan.JobID != report.JobID || current.Plan.Plan.EnrollmentID != report.EnrollmentID || current.Plan.Plan.Revision != report.Revision {
				return nil, errors.New("stale_job")
			}
			if report.Sequence > current.Acknowledged {
				current.Acknowledged = report.Sequence
			}
			return current, nil
		}); err != nil {
			return err
		}
	}
}

func (m *Manager) transition(jobID, state, code, running string, installed *managed.RPMPackage, collection ...string) error {
	return m.Store.Change(func(job *Job) (*Job, error) {
		if job == nil || job.Plan.Plan.JobID != jobID {
			return nil, errors.New("stale_job")
		}
		if job.Terminal() {
			return job, nil
		}
		before := len(job.Reports)
		job.Append(state, code, running, installed, m.now())
		if len(job.Reports) > before && len(collection) != 0 {
			job.Reports[len(job.Reports)-1].CollectionCheck = collection[0]
		}
		if job.Last().Validate() != nil {
			return nil, errors.New("state_unavailable")
		}
		return job, nil
	})
}

// Once serializes staging independently of the helper's apply lock. No package
// mutation runs in the agent, whose filesystem remains protected by systemd.
func (m *Manager) Once(ctx context.Context, client Client, identity Identity, inventory managed.UpdateInventory) error {
	if err := m.Recover(ctx, client, identity, inventory); err != nil {
		return err
	}
	if !inventory.Supported || !inventory.Enabled {
		return nil
	}
	lock, err := m.Store.lock(".worker.lock")
	if err != nil {
		return err
	}
	defer unlock(lock)
	removal, err := m.Store.readRemoval()
	if err != nil {
		return err
	}
	if removal.reserved(m.now()) {
		if removal.matches(identity.AgentID, identity.EnrollmentID) {
			return nil
		}
		// A previous enrollment's journal cannot reserve a new generation,
		// but a worker still holding the package lock must finish first.
		apply, err := m.Store.lock(".apply.lock")
		if err != nil {
			return err
		}
		unlock(apply)
	}
	if err := m.Store.cleanTemporaryFiles(); err != nil {
		return err
	}
	if err := m.Flush(ctx, client, identity); err != nil {
		return err
	}
	job, err := m.Store.Read()
	if err != nil {
		return err
	}
	if job != nil && !job.Terminal() && job.Plan.Plan.EnrollmentID == identity.EnrollmentID {
		if job.Last().State == "installing" {
			return m.Reconcile(ctx, job, inventory.RunningVersion)
		}
		return m.stage(ctx, client, identity, inventory, job)
	}
	signed, err := client.DesiredUpdate(ctx)
	if err != nil || signed == nil {
		return err
	}
	keys, err := identity.Keys()
	if err != nil {
		return errors.New("identity_unavailable")
	}
	var minimum uint64
	if job != nil && job.Plan.Plan.EnrollmentID == identity.EnrollmentID {
		minimum = job.Plan.Plan.Revision
	}
	plan, err := managed.VerifyUpdatePlan(*signed, keys, m.publisherKeys(), identity.AgentID, identity.EnrollmentID, minimum, m.now())
	if err != nil {
		return errors.New("signature_invalid")
	}
	if job != nil && job.Plan.Plan.EnrollmentID == identity.EnrollmentID && (job.Plan.Plan.Revision == plan.Revision || job.Plan.Plan.JobID == plan.JobID) {
		oldDigest, _ := managed.UpdatePlanDigest(job.Plan.Plan)
		newDigest, _ := managed.UpdatePlanDigest(plan)
		if oldDigest != newDigest || job.Plan.Plan.JobID != plan.JobID {
			return errors.New("stale_job")
		}
		return nil
	}
	baseline := CollectionBaseline{CapturedAt: m.now()}
	if m.CaptureCollection != nil {
		baseline, err = m.CaptureCollection(ctx)
		if err != nil {
			return err
		}
	}
	job = &Job{SchemaVersion: 1, Plan: *signed, KeyID: identity.KeyID, PublicKey: identity.PublicKey, Collection: baseline}
	job.Append("downloading", "", inventory.RunningVersion, inventory.InstalledPackage, m.now())
	if err := m.Store.Change(func(previous *Job) (*Job, error) {
		if previous != nil && !previous.Terminal() {
			return nil, ErrBusy
		}
		return job, nil
	}); err != nil {
		return err
	}
	return m.stage(ctx, client, identity, inventory, job)
}

func (m *Manager) stage(ctx context.Context, client Client, identity Identity, inventory managed.UpdateInventory, job *Job) error {
	plan := job.Plan.Plan
	fail := func(code string) error {
		return m.Store.Change(func(current *Job) (*Job, error) {
			if current == nil || current.Plan.Plan.JobID != plan.JobID {
				return nil, errors.New("stale_job")
			}
			if !current.Terminal() && current.Last().State != "installing" {
				current.Append("failed", code, inventory.RunningVersion, inventory.InstalledPackage, m.now())
			}
			return current, nil
		})
	}
	keys, err := identity.Keys()
	if err != nil {
		return fail("identity_unavailable")
	}
	if _, err := managed.VerifyUpdatePlan(job.Plan, keys, m.publisherKeys(), identity.AgentID, identity.EnrollmentID, plan.Revision, m.now()); err != nil {
		return fail("expired")
	}
	if plan.Release.OSFamily != inventory.OSFamily || plan.Release.OSMajor != inventory.OSMajor || plan.Release.Package.Arch != inventory.Arch {
		return fail("target_mismatch")
	}
	if len(PackageVersion(plan.Release.Package)) > 128 {
		return fail("unsupported_package")
	}
	if inventory.InstalledPackage == nil {
		return fail("unsupported_package")
	}
	if *inventory.InstalledPackage == plan.Release.Package {
		if job.Authorization == nil {
			return fail("precondition_changed")
		}
		return m.Reconcile(ctx, job, inventory.RunningVersion)
	}
	if *inventory.InstalledPackage != plan.ExpectedPackage {
		return fail("precondition_changed")
	}
	if job.Last().State == "downloading" {
		if err := m.download(ctx, client, plan.Release); err != nil {
			return fail(downloadCode(err))
		}
		if err := m.verifyArtifact(plan.Release); err != nil {
			return fail(downloadCode(err))
		}
		candidate, err := QueryPackage(ctx, m.Runner, filepath.Join(m.Store.Directory, "artifact.rpm"))
		if err != nil || candidate != plan.Release.Package {
			return fail("metadata_mismatch")
		}
		if err := m.transition(plan.JobID, "ready", "", inventory.RunningVersion, inventory.InstalledPackage); err != nil {
			return err
		}
	}
	// Claim only after the complete download has passed its size/hash/header gate.
	if err := m.Flush(ctx, client, identity); err != nil {
		return err
	}
	if m.CheckLocal != nil {
		if err := m.CheckLocal(ctx, plan); err != nil {
			if err.Error() == "service_unavailable" {
				return err
			}
			return fail(downloadCode(err))
		}
	}
	if m.CurrentIdentity != nil {
		current, err := m.CurrentIdentity(ctx)
		if err != nil || current != identity {
			return fail("identity_unavailable")
		}
	}
	authorization, err := client.ClaimUpdate(ctx, managed.UpdateClaim{JobID: plan.JobID, EnrollmentID: plan.EnrollmentID, Revision: plan.Revision})
	if err != nil {
		var rejection interface{ UpdateClaimRejected() bool }
		if errors.As(err, &rejection) && rejection.UpdateClaimRejected() {
			return fail("stale_job")
		}
		return err
	}
	if _, err := managed.VerifyUpdateAuthorization(authorization, keys, plan, m.now()); err != nil {
		return fail("signature_invalid")
	}
	if err := m.Store.Change(func(current *Job) (*Job, error) {
		if current == nil || current.Plan.Plan.JobID != plan.JobID || current.Last().State != "ready" {
			return nil, errors.New("stale_job")
		}
		current.Authorization = &authorization
		return current, nil
	}); err != nil {
		return err
	}
	startCtx, cancelStart := context.WithTimeout(ctx, 10*time.Second)
	_, err = m.Runner.Run(startCtx, "/usr/bin/systemctl", "start", "--no-block", "sentinel-updater.service")
	cancelStart()
	if err != nil {
		return errors.New("queue_failed")
	}
	return nil
}

func downloadCode(err error) string {
	if managed.ValidUpdateCode(err.Error()) && err.Error() != "" {
		return err.Error()
	}
	return "download_failed"
}

func (m *Manager) download(ctx context.Context, client Client, release managed.UpdateRelease) error {
	file, err := os.CreateTemp(m.Store.Directory, ".download-")
	if err != nil {
		return errors.New("state_unavailable")
	}
	defer os.Remove(file.Name())
	err = client.DownloadUpdateArtifact(ctx, release, file)
	if err == nil {
		err = file.Sync()
	}
	if err == nil {
		err = file.Chmod(0o400)
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(file.Name(), filepath.Join(m.Store.Directory, "artifact.rpm")); err != nil {
		return errors.New("state_unavailable")
	}
	return m.Store.syncDirectory()
}
