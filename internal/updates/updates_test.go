package updates

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

func TestStageAndIndependentApplyExactRetry(t *testing.T) {
	m, c, id, inventory, runner, _ := fixture(t)
	ctx := context.Background()
	if err := m.Once(ctx, c, id, inventory); err != nil {
		t.Fatal(err)
	}
	job, _ := m.Store.Read()
	if job.Last().State != "ready" || job.Authorization == nil || c.claims != 1 || runner.installCount != 0 {
		t.Fatalf("agent crossed the apply boundary: %#v", job)
	}
	if len(c.reports) != 2 || c.reports[0].State != "downloading" || c.reports[1].State != "ready" || job.Acknowledged != 2 {
		t.Fatal("claim preceded durable ready report ACKs")
	}
	if err := m.Apply(ctx); err != nil {
		t.Fatal(err)
	}
	job, _ = m.Store.Read()
	if job.Last().State != "succeeded" || job.Last().RunningVersion != PackageVersion(c.plan.Plan.Release.Package) || runner.installCount != 1 {
		t.Fatalf("target was not verified: %#v", job)
	}
	if err := m.Apply(ctx); err != nil || runner.installCount != 1 {
		t.Fatal("terminal job repeated installation")
	}
	c.loseReply = true
	start := len(c.reports)
	if m.Flush(ctx, c, id) == nil {
		t.Fatal("lost reply was not surfaced")
	}
	first, _ := json.Marshal(c.reports[start])
	if err := m.Flush(ctx, c, id); err != nil {
		t.Fatal(err)
	}
	retry, _ := json.Marshal(c.reports[start+1])
	if !bytes.Equal(first, retry) {
		t.Fatal("report retry changed stable bytes")
	}
	job, _ = m.Store.Read()
	if job.Acknowledged != 4 || len(job.Reports) != 4 {
		t.Fatalf("missing ordered reports: %#v", job)
	}
	for _, call := range runner.commands {
		if strings.Contains(call, "--oldpackage") || strings.Contains(call, "--replacepkgs") {
			t.Fatal("unsafe RPM option")
		}
	}
}

func TestClaimRequiresCompleteHashAndMetadata(t *testing.T) {
	for _, failure := range []string{"hash", "size", "metadata"} {
		t.Run(failure, func(t *testing.T) {
			m, c, id, inventory, runner, _ := fixture(t)
			switch failure {
			case "hash":
				c.artifact[0] = 'x'
			case "size":
				c.artifact = append(c.artifact, 'x')
			case "metadata":
				runner.candidate.Release = "99.el9"
			}
			if err := m.Once(context.Background(), c, id, inventory); err != nil {
				t.Fatal(err)
			}
			job, _ := m.Store.Read()
			if job.Last().State != "failed" || c.claims != 0 || runner.installCount != 0 {
				t.Fatalf("invalid artifact reached claim: %#v", job)
			}
		})
	}
}

func TestHelperRejectsChangedAuthorizationAndLocalPreconditions(t *testing.T) {
	for _, failure := range []string{"lease", "lease_after_test", "lease_during_final_query", "lease_during_local_gate", "key", "enrollment", "disabled", "installed", "installed_after_test", "artifact", "symlink", "mode", "test"} {
		t.Run(failure, func(t *testing.T) {
			m, c, id, inventory, runner, now := fixture(t)
			if err := m.Once(context.Background(), c, id, inventory); err != nil {
				t.Fatal(err)
			}
			switch failure {
			case "lease":
				*now = now.Add(3 * time.Minute)
			case "lease_after_test":
				runner.beforeTest = func() { *now = now.Add(3 * time.Minute) }
			case "lease_during_final_query":
				afterTest := false
				runner.beforeTest = func() { afterTest = true }
				runner.beforeQuery = func() {
					if afterTest {
						*now = now.Add(3 * time.Minute)
						afterTest = false
					}
				}
			case "lease_during_local_gate":
				checks := 0
				m.CheckLocal = func(context.Context, managed.UpdatePlan) error {
					checks++
					if checks == 2 {
						*now = now.Add(3 * time.Minute)
					}
					return nil
				}
			case "key":
				m.CurrentIdentity = func(context.Context) (Identity, error) { value := id; value.PublicKey = "different"; return value, nil }
			case "enrollment":
				m.CurrentIdentity = func(context.Context) (Identity, error) { value := id; value.EnrollmentID = "other"; return value, nil }
			case "disabled":
				m.CheckLocal = func(context.Context, managed.UpdatePlan) error { return errors.New("disabled") }
			case "installed":
				runner.installed.Release = "25.el9"
			case "installed_after_test":
				runner.beforeTest = func() { runner.installed.Release = "25.el9" }
			case "artifact":
				os.Chmod(filepath.Join(m.Store.Directory, "artifact.rpm"), 0o600)
				os.WriteFile(filepath.Join(m.Store.Directory, "artifact.rpm"), []byte("changed"), 0o600)
			case "symlink":
				os.Remove(filepath.Join(m.Store.Directory, "artifact.rpm"))
				os.Symlink("/etc/passwd", filepath.Join(m.Store.Directory, "artifact.rpm"))
			case "mode":
				os.Chmod(filepath.Join(m.Store.Directory, "artifact.rpm"), 0o666)
			case "test":
				runner.testError = errors.New("PRIVATE RAW STDERR MUST NOT PERSIST")
			}
			if err := m.Apply(context.Background()); err != nil {
				t.Fatal(err)
			}
			job, _ := m.Store.Read()
			if job.Last().State != "failed" || runner.installCount != 0 || !managed.ValidUpdateCode(job.Last().ErrorCode) {
				t.Fatalf("unsafe precondition applied: %#v", job)
			}
			data, _ := json.Marshal(job)
			if bytes.Contains(data, []byte("PRIVATE")) {
				t.Fatal("raw diagnostics entered the journal")
			}
		})
	}
}

func TestUnsupportedInventoryStillReportsInterruptedInstalledTarget(t *testing.T) {
	m, c, id, inventory, runner, _ := fixture(t)
	ctx := context.Background()
	if err := m.Once(ctx, c, id, inventory); err != nil {
		t.Fatal(err)
	}
	if err := m.transition(c.plan.Plan.JobID, "installing", "", inventory.RunningVersion, inventory.InstalledPackage); err != nil {
		t.Fatal(err)
	}
	runner.installed = runner.candidate
	m.Healthy = func(context.Context, managed.UpdatePlan) bool { return false }
	inventory.Supported = false
	inventory.ReasonCode = "precondition_changed"
	inventory.InstalledPackage = &runner.installed
	if err := m.Once(ctx, c, id, inventory); err != nil {
		t.Fatal(err)
	}
	job, _ := m.Store.Read()
	if job.Last().State != "failed" || job.Last().ErrorCode != "interrupted" || job.Last().RunningVersion != inventory.RunningVersion || job.Last().InstalledPackage.Release != runner.candidate.Release || job.Acknowledged != uint64(len(job.Reports)) {
		t.Fatalf("unsupported inventory stranded prior work: %#v", job)
	}
	if err := m.Once(ctx, c, id, inventory); err != nil || runner.installCount != 0 {
		t.Fatal("interrupted installation repeated")
	}
}

func TestOptOutFlushesPriorResultAndNewEnrollmentArchivesOldQueue(t *testing.T) {
	m, c, id, inventory, _, _ := fixture(t)
	if err := m.Once(context.Background(), c, id, inventory); err != nil {
		t.Fatal(err)
	}
	inventory.Enabled = false
	if err := m.Once(context.Background(), c, id, inventory); err != nil {
		t.Fatal(err)
	}
	job, _ := m.Store.Read()
	if job.Last().ErrorCode != "disabled" || job.Acknowledged != uint64(len(job.Reports)) {
		t.Fatal("opt-out stranded its result")
	}
	id.EnrollmentID = "new-enrollment"
	c.plan = nil
	if err := m.Once(context.Background(), c, id, inventory); err != nil {
		t.Fatal(err)
	}
	job, err := m.Store.Read()
	if err != nil || job != nil {
		t.Fatal("foreign enrollment still blocks current identity")
	}
	if _, err := os.Stat(filepath.Join(m.Store.Directory, "orphaned-job.json")); err != nil {
		t.Fatal("foreign queue was not retained")
	}
}

func TestFailedResultUsesObservedDaemonVersionNotHelperBuild(t *testing.T) {
	m, c, id, inventory, runner, _ := fixture(t)
	if err := m.Once(context.Background(), c, id, inventory); err != nil {
		t.Fatal(err)
	}
	runner.installError = errors.New("private scriptlet error")
	m.RunningVersion = func(context.Context) string { return "0.1.0-24.el9.x86_64" }
	if err := m.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	job, _ := m.Store.Read()
	if job.Last().RunningVersion != "0.1.0-24.el9.x86_64" || job.Last().ErrorCode != "install_failed" {
		t.Fatalf("helper version substituted for actual daemon: %#v", job.Last())
	}
}

func TestEpochOnlyUpgradeRequiresNewRunningDaemon(t *testing.T) {
	m, c, id, inventory, runner, _ := fixture(t)
	plan := c.plan.Plan
	plan.Release.Package = plan.ExpectedPackage
	plan.Release.Package.Epoch = 2
	manifest := plan.Release.Publisher.Manifest
	manifest.Package = plan.Release.Package
	plan.Release.Publisher, _ = managed.SignReleaseManifest(manifest, "publisher", c.publisherPrivate)
	signed, err := managed.SignUpdatePlan(plan, "key", c.private)
	if err != nil {
		t.Fatal(err)
	}
	c.plan = &signed
	runner.candidate = plan.Release.Package
	m.Healthy = func(_ context.Context, target managed.UpdatePlan) bool {
		return inventory.RunningVersion == PackageVersion(target.Release.Package)
	}
	m.RunningVersion = func(context.Context) string { return inventory.RunningVersion }
	if err := m.Once(context.Background(), c, id, inventory); err != nil {
		t.Fatal(err)
	}
	if err := m.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	job, _ := m.Store.Read()
	if job.Last().State != "failed" || job.Last().ErrorCode != "health_check_failed" || job.Last().InstalledPackage.Epoch != 2 || job.Last().RunningVersion == PackageVersion(plan.Release.Package) {
		t.Fatalf("epoch-only package replacement was mistaken for a new daemon: %#v", job.Last())
	}
}

func TestConcurrentHelperCannotRepeatApplyAndReporterPreservesOutcome(t *testing.T) {
	m, c, id, inventory, runner, _ := fixture(t)
	ctx := context.Background()
	if err := m.Once(ctx, c, id, inventory); err != nil {
		t.Fatal(err)
	}
	started, release := make(chan struct{}), make(chan struct{})
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	runner.beforeInstall = func() { close(started); <-release }
	done := make(chan error, 1)
	go func() { done <- m.Apply(ctx) }()
	select {
	case <-started:
	case err := <-done:
		t.Fatalf("helper exited before apply: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("helper did not reach fake RPM")
	}
	if err := m.Apply(ctx); !errors.Is(err, ErrBusy) {
		t.Fatalf("parallel helper did not refuse apply: %v", err)
	}
	if err := m.Flush(ctx, c, id); err != nil {
		t.Fatal(err)
	}
	close(release)
	released = true
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := m.Flush(ctx, c, id); err != nil {
		t.Fatal(err)
	}
	job, _ := m.Store.Read()
	if runner.installCount != 1 || job.Last().State != "succeeded" || job.Acknowledged != uint64(len(job.Reports)) {
		t.Fatalf("concurrent ACK lost final result: %#v", job)
	}
}

func TestStaleReconcileAndStageCannotChangeCompletedOrApplyingJob(t *testing.T) {
	m, c, id, inventory, runner, _ := fixture(t)
	ctx := context.Background()
	if err := m.Once(ctx, c, id, inventory); err != nil {
		t.Fatal(err)
	}
	staleReady, _ := m.Store.Read()
	if err := m.transition(c.plan.Plan.JobID, "installing", "", inventory.RunningVersion, inventory.InstalledPackage); err != nil {
		t.Fatal(err)
	}
	staleInstalling, _ := m.Store.Read()
	changed := *inventory.InstalledPackage
	changed.Release = "25.el9"
	inventory.InstalledPackage = &changed
	if err := m.stage(ctx, c, id, inventory, staleReady); err != nil {
		t.Fatal(err)
	}
	job, _ := m.Store.Read()
	if job.Last().State != "installing" {
		t.Fatal("stale staging failure overwrote applying job")
	}
	runner.installed = runner.candidate
	if err := m.transition(c.plan.Plan.JobID, "succeeded", "", PackageVersion(runner.installed), &runner.installed); err != nil {
		t.Fatal(err)
	}
	m.Healthy = func(context.Context, managed.UpdatePlan) bool { return false }
	if err := m.Reconcile(ctx, staleInstalling, "unknown"); err != nil {
		t.Fatal(err)
	}
	job, _ = m.Store.Read()
	if job.Last().State != "succeeded" || len(job.Reports) != 4 {
		t.Fatalf("stale reconcile regressed terminal job: %#v", job)
	}
}

func TestTerminalDecisionBeforeHelperClaimPreventsRPM(t *testing.T) {
	m, c, id, inventory, runner, _ := fixture(t)
	if err := m.Once(context.Background(), c, id, inventory); err != nil {
		t.Fatal(err)
	}
	checks := 0
	m.CurrentIdentity = func(context.Context) (Identity, error) {
		checks++
		if checks == 1 {
			if err := m.transition(c.plan.Plan.JobID, "failed", "disabled", inventory.RunningVersion, inventory.InstalledPackage); err != nil {
				t.Fatal(err)
			}
		}
		return id, nil
	}
	if err := m.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	job, _ := m.Store.Read()
	if runner.installCount != 0 || job.Last().ErrorCode != "disabled" {
		t.Fatal("helper executed after losing its durable claim")
	}
}

type rejectedClaim struct{}

func (rejectedClaim) Error() string             { return "claim rejected" }
func (rejectedClaim) UpdateClaimRejected() bool { return true }

func TestRejectedOldClaimDoesNotBlockNewDesiredJob(t *testing.T) {
	m, c, id, inventory, runner, _ := fixture(t)
	c.claimError = rejectedClaim{}
	if err := m.Once(context.Background(), c, id, inventory); err != nil {
		t.Fatal(err)
	}
	job, _ := m.Store.Read()
	if job.Last().ErrorCode != "stale_job" || job.Last().State != "failed" {
		t.Fatal("canceled claim remained stuck ready")
	}
	plan := c.plan.Plan
	plan.JobID = "new-job"
	plan.RolloutID = "new-rollout"
	plan.Revision++
	signed, err := managed.SignUpdatePlan(plan, "key", c.private)
	if err != nil {
		t.Fatal(err)
	}
	c.plan, c.claimError = &signed, nil
	if err := m.Once(context.Background(), c, id, inventory); err != nil {
		t.Fatal(err)
	}
	job, _ = m.Store.Read()
	if job.Plan.Plan.JobID != "new-job" || job.Last().State != "ready" || runner.installCount != 0 {
		t.Fatal("old canceled job blocked new staging")
	}
}

func TestInterruptedJobReconcilesWithoutReinstall(t *testing.T) {
	for _, target := range []bool{false, true} {
		m, c, id, inventory, runner, _ := fixture(t)
		if err := m.Once(context.Background(), c, id, inventory); err != nil {
			t.Fatal(err)
		}
		if err := m.transition(c.plan.Plan.JobID, "installing", "", inventory.RunningVersion, inventory.InstalledPackage); err != nil {
			t.Fatal(err)
		}
		if target {
			runner.installed = runner.candidate
		}
		if err := m.Apply(context.Background()); err != nil {
			t.Fatal(err)
		}
		job, _ := m.Store.Read()
		want := "failed"
		if target {
			want = "succeeded"
		}
		if job.Last().State != want || runner.installCount != 0 {
			t.Fatalf("interrupted claim was repeated: %#v", job)
		}
	}
}

func TestSameRevisionDifferentPlanAndOtherEnrollmentRejected(t *testing.T) {
	m, c, id, inventory, runner, _ := fixture(t)
	if err := m.Once(context.Background(), c, id, inventory); err != nil {
		t.Fatal(err)
	}
	if err := m.transition(c.plan.Plan.JobID, "failed", "interrupted", inventory.RunningVersion, inventory.InstalledPackage); err != nil {
		t.Fatal(err)
	}
	changed := c.plan.Plan
	changed.Release.ID = "different-release"
	signed, _ := managed.SignUpdatePlan(changed, "key", c.private)
	c.plan = &signed
	if err := m.Once(context.Background(), c, id, inventory); err == nil || err.Error() != "stale_job" {
		t.Fatalf("same-revision conflict accepted: %v", err)
	}
	id.EnrollmentID = "new-enrollment"
	if err := m.Once(context.Background(), c, id, inventory); err == nil || runner.installCount != 0 {
		t.Fatal("other enrollment replay accepted")
	}
}

func TestJobDirectoryAndJournalRejectSymlinksAndPermissions(t *testing.T) {
	m, c, id, inventory, _, _ := fixture(t)
	if err := m.Once(context.Background(), c, id, inventory); err != nil {
		t.Fatal(err)
	}
	jobPath := filepath.Join(m.Store.Directory, "job.json")
	os.Chmod(jobPath, 0o644)
	if _, err := m.Store.Read(); err == nil {
		t.Fatal("public job file accepted")
	}
	os.Remove(jobPath)
	os.Symlink("/etc/passwd", jobPath)
	if _, err := m.Store.Read(); err == nil {
		t.Fatal("symlink job accepted")
	}
	parent := t.TempDir()
	real := filepath.Join(parent, "real")
	os.Mkdir(real, 0o700)
	os.Symlink(real, filepath.Join(parent, "link"))
	m.Store.Directory = filepath.Join(parent, "link", "updates")
	if err := m.Store.Prepare(); err == nil {
		t.Fatal("symlink parent accepted")
	}
}
