package updates

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

func (m *Manager) verifyArtifact(release managed.UpdateRelease) error {
	path := filepath.Join(m.Store.Directory, "artifact.rpm")
	if err := secureRegular(path, m.Store.OwnerUID, true); err != nil {
		return err
	}
	file, err := os.Open(path)
	if err != nil {
		return errors.New("state_unavailable")
	}
	defer file.Close()
	hash := sha256.New()
	size, err := io.Copy(hash, io.LimitReader(file, release.Size+1))
	if err != nil || size != release.Size {
		return errors.New("size_mismatch")
	}
	if hex.EncodeToString(hash.Sum(nil)) != release.SHA256 {
		return errors.New("hash_mismatch")
	}
	return nil
}

func (m *Manager) Reconcile(ctx context.Context, job *Job, running string) error {
	lock, err := m.Store.lock(".apply.lock")
	if errors.Is(err, ErrBusy) {
		return nil
	}
	if err != nil {
		return err
	}
	defer unlock(lock)
	return m.reconcile(ctx, job, running)
}

func (m *Manager) reconcile(ctx context.Context, job *Job, running string) error {
	current, err := m.Store.Read()
	if err != nil || current == nil {
		return err
	}
	if current.Plan.Plan.JobID != job.Plan.Plan.JobID || current.Plan.Plan.EnrollmentID != job.Plan.Plan.EnrollmentID || current.Plan.Plan.Revision != job.Plan.Plan.Revision {
		return errors.New("stale_job")
	}
	if current.Terminal() {
		return nil
	}
	if current.Last().State != "installing" && (current.Last().State != "ready" || current.Authorization == nil) {
		return nil
	}
	job = current
	installed, err := QueryPackage(ctx, m.Runner, "")
	var actual *managed.RPMPackage
	if err == nil {
		actual = &installed
	}
	return m.verifyOutcome(ctx, job, actual, "interrupted")
}

// Apply is called only by the independent root systemd service. A prior durable
// installing claim is reconciled; it never causes another RPM invocation.
func (m *Manager) Apply(ctx context.Context) error {
	lock, err := m.Store.lock(".apply.lock")
	if err != nil {
		return err
	}
	defer unlock(lock)
	job, err := m.Store.Read()
	if err != nil || job == nil || job.Terminal() {
		return err
	}
	if job.Last().State == "installing" {
		return m.reconcile(ctx, job, m.running(ctx))
	}
	if job.Last().State != "ready" || job.Authorization == nil {
		return nil
	}
	plan := job.Plan.Plan
	var installed *managed.RPMPackage
	fail := func(code string) error {
		if !managed.ValidUpdateCode(code) || code == "" {
			code = "verification_failed"
		}
		return m.transition(plan.JobID, "failed", code, m.running(ctx), installed)
	}
	if len(PackageVersion(plan.Release.Package)) > 128 {
		return fail("unsupported_package")
	}
	identity := Identity{plan.AgentID, plan.EnrollmentID, job.KeyID, job.PublicKey}
	keys, err := identity.Keys()
	if err != nil {
		return fail("identity_unavailable")
	}
	verify := func() error {
		if m.CheckLocal != nil {
			if err := m.CheckLocal(ctx, plan); err != nil {
				return err
			}
		}
		if m.CurrentIdentity != nil {
			current, err := m.CurrentIdentity(ctx)
			if err != nil || current != identity {
				return errors.New("identity_unavailable")
			}
		}
		if _, err := managed.VerifyUpdatePlan(job.Plan, keys, m.publisherKeys(), plan.AgentID, plan.EnrollmentID, plan.Revision, m.now()); err != nil {
			return errors.New("signature_invalid")
		}
		if _, err := managed.VerifyUpdateAuthorization(*job.Authorization, keys, plan, m.now()); err != nil {
			return errors.New("expired")
		}
		return nil
	}
	if err := verify(); err != nil {
		return fail(err.Error())
	}
	family, major, arch := HostPlatform("/etc/os-release")
	if m.Platform != nil {
		family, major, arch = m.Platform()
	}
	if plan.Release.OSFamily != family || plan.Release.OSMajor != major || plan.Release.Package.Arch != arch {
		return fail("target_mismatch")
	}
	current, err := QueryPackage(ctx, m.Runner, "")
	if err != nil {
		return fail("rpm_unavailable")
	}
	installed = &current
	if current == plan.Release.Package {
		return m.reconcile(ctx, job, m.running(ctx))
	}
	if current != plan.ExpectedPackage {
		return fail("precondition_changed")
	}
	if err := m.verifyArtifact(plan.Release); err != nil {
		return fail(err.Error())
	}
	artifact := filepath.Join(m.Store.Directory, "artifact.rpm")
	candidate, err := QueryPackage(ctx, m.Runner, artifact)
	if err != nil || candidate != plan.Release.Package {
		return fail("metadata_mismatch")
	}
	claimed := false
	running := m.running(ctx)
	if err := m.Store.Change(func(current *Job) (*Job, error) {
		if current == nil {
			return nil, errors.New("stale_job")
		}
		if current.Plan.Plan.JobID != plan.JobID || current.Plan.Plan.EnrollmentID != plan.EnrollmentID || current.Plan.Plan.Revision != plan.Revision || current.Terminal() || current.Last().State != "ready" {
			return current, nil
		}
		current.Append("installing", "", running, installed, m.now())
		claimed = true
		return current, nil
	}); err != nil {
		return err
	}
	if !claimed {
		return nil
	}
	testCtx, cancelTest := context.WithTimeout(ctx, 30*time.Second)
	_, err = m.Runner.Run(testCtx, "/usr/bin/rpm", "-Uvh", "--test", "--", artifact)
	cancelTest()
	if err != nil {
		return fail("rpm_test_failed")
	}
	current, err = QueryPackage(ctx, m.Runner, "")
	if err == nil {
		installed = &current
	} else {
		installed = nil
	}
	if err != nil || current != plan.ExpectedPackage {
		return fail("precondition_changed")
	}
	// All potentially blocking precondition reads precede the final lease check.
	// No filesystem/network query occurs between this check and RPM launch.
	if err := verify(); err != nil {
		return fail(err.Error())
	}
	applyCtx, cancelApply := context.WithTimeout(ctx, 5*time.Minute)
	_, err = m.Runner.Run(applyCtx, "/usr/bin/rpm", "-Uvh", "--", artifact)
	interrupted := applyCtx.Err() != nil
	cancelApply()
	installed = nil
	if actual, queryErr := QueryPackage(ctx, m.Runner, ""); queryErr == nil {
		installed = &actual
	}
	if err != nil {
		if interrupted {
			return fail("interrupted")
		}
		return fail("install_failed")
	}
	restartCtx, cancelRestart := context.WithTimeout(ctx, 30*time.Second)
	_, err = m.Runner.Run(restartCtx, "/usr/bin/systemctl", "restart", "sentineld.service")
	cancelRestart()
	if err != nil {
		return fail("restart_failed")
	}
	return m.verifyOutcome(ctx, job, installed, "health_check_failed")
}
