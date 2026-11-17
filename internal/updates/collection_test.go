package updates

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"xe-antishell/internal/model"
)

func collectionStatus(collector string, started, verified time.Time) model.AgentStatus {
	collectorKey := "collector.tetragon"
	if collector == "audit-dispatcher" {
		collectorKey = "collector.audit"
	}
	capability := model.Capability{Implementation: "implemented", RuntimeState: "active", VerifiedAt: &verified}
	return model.AgentStatus{StartedAt: started, Collector: collector,
		CollectorHealth:  &model.CollectorHealth{Name: collector, Running: true},
		CapabilityReport: &model.CapabilityReport{Capabilities: map[string]model.Capability{collectorKey: capability, "observation.process_exec": capability}}}
}

func TestCollectionProofRequiresSameLiveSourceAndNewDaemonReceipt(t *testing.T) {
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	before := collectionStatus("tetragon-json", now.Add(-time.Hour), now.Add(-time.Second))
	baseline := BaselineFromStatus(before, now)
	if !baseline.Active {
		t.Fatal("actual active baseline was lost")
	}
	unverified := before
	value := unverified.CapabilityReport.Capabilities["observation.process_exec"]
	value.RuntimeState, value.VerifiedAt = "unverified", nil
	unverified.CapabilityReport = &model.CapabilityReport{Capabilities: map[string]model.Capability{"observation.process_exec": value}}
	startup := BaselineFromStatus(unverified, now)
	if !startup.Active || startup.PriorExecVerified {
		t.Fatal("running startup source was hidden as not applicable")
	}
	for _, scenario := range []string{"verified", "stream_dead", "collector_changed", "old_receipt", "same_daemon"} {
		post := collectionStatus("tetragon-json", now.Add(time.Second), now.Add(2*time.Second))
		switch scenario {
		case "stream_dead":
			post.CollectorHealth.Running = false
		case "collector_changed":
			post = collectionStatus("audit-dispatcher", now.Add(time.Second), now.Add(2*time.Second))
		case "old_receipt":
			old := now.Add(-time.Second)
			value := post.CapabilityReport.Capabilities["observation.process_exec"]
			value.VerifiedAt = &old
			post.CapabilityReport.Capabilities["observation.process_exec"] = value
		case "same_daemon":
			post.StartedAt = before.StartedAt
		}
		if CollectionMatches(baseline, post) != (scenario == "verified") {
			t.Fatalf("incorrect collection proof: %s", scenario)
		}
	}
}

func TestPostInstallReportsActualCollectionOutcome(t *testing.T) {
	for _, scenario := range []string{"verified", "stream_dead", "collector_changed", "previously_unsupported", "audit_dead", "startup_unverified_dead"} {
		t.Run(scenario, func(t *testing.T) {
			m, c, id, inventory, runner, now := fixture(t)
			before := collectionStatus("tetragon-json", now.Add(-time.Hour), now.Add(-time.Second))
			post := collectionStatus("tetragon-json", now.Add(time.Second), now.Add(2*time.Second))
			post.Version = PackageVersion(runner.candidate)
			switch scenario {
			case "stream_dead":
				post.CollectorHealth.Running = false
			case "collector_changed":
				post = collectionStatus("audit-dispatcher", now.Add(time.Second), now.Add(2*time.Second))
			case "previously_unsupported":
				before.Collector = "disabled"
				before.CollectorHealth = nil
				before.CapabilityReport = nil
			case "audit_dead":
				before = collectionStatus("audit-dispatcher", now.Add(-time.Hour), now.Add(-time.Second))
				post = collectionStatus("audit-dispatcher", now.Add(time.Second), now.Add(2*time.Second))
				post.CollectorHealth.Running = false
				post.Version = PackageVersion(runner.candidate)
			case "startup_unverified_dead":
				before.CapabilityReport = nil
				post.CollectorHealth.Running = false
			}
			post.Version = PackageVersion(runner.candidate)
			m.CaptureCollection = func(context.Context) (CollectionBaseline, error) { return BaselineFromStatus(before, *now), nil }
			m.VerifyCollection = func(_ context.Context, baseline CollectionBaseline) bool { return CollectionMatches(baseline, post) }
			m.RunningVersion = func(context.Context) string { return post.Version }
			if err := m.Once(context.Background(), c, id, inventory); err != nil {
				t.Fatal(err)
			}
			if err := m.Apply(context.Background()); err != nil {
				t.Fatal(err)
			}
			job, err := m.Store.Read()
			if err != nil {
				t.Fatal(err)
			}
			wantState, wantCheck := "failed", "failed"
			if scenario == "verified" {
				wantState, wantCheck = "succeeded", "verified"
			}
			if scenario == "previously_unsupported" {
				wantState, wantCheck = "succeeded", "not_applicable"
			}
			if job.Last().State != wantState || job.Last().CollectionCheck != wantCheck || job.Last().RunningVersion != post.Version {
				t.Fatalf("incorrect post-install outcome: %#v", job.Last())
			}
			if wantState == "failed" && job.Last().ErrorCode != "collection_check_failed" {
				t.Fatal("collector regression was hidden as package success")
			}
			if err := m.Apply(context.Background()); err != nil || runner.installCount != 1 {
				t.Fatal("collection failure caused another RPM transaction")
			}
			if scenario == "audit_dead" {
				found := false
				for _, command := range runner.commands {
					if strings.Contains(command, "/bin/sh -c /usr/bin/true") {
						found = true
					}
				}
				if !found {
					t.Fatal("audit probe did not use a real bounded harmless exec")
				}
			}
		})
	}
}

func TestUnobservedBaselineIsNotReportedAsNotApplicable(t *testing.T) {
	m, c, id, inventory, runner, _ := fixture(t)
	m.CaptureCollection = func(context.Context) (CollectionBaseline, error) {
		return CollectionBaseline{}, errors.New("service_unavailable")
	}
	if err := m.Once(context.Background(), c, id, inventory); err == nil {
		t.Fatal("unavailable baseline was silently skipped")
	}
	if c.claims != 0 || runner.installCount != 0 {
		t.Fatal("unknown source baseline reached apply")
	}
}

func TestInterruptedInstalledTargetStillRequiresCollectionProof(t *testing.T) {
	for _, verified := range []bool{false, true} {
		m, c, id, inventory, runner, now := fixture(t)
		before := collectionStatus("tetragon-json", now.Add(-time.Hour), now.Add(-time.Second))
		m.CaptureCollection = func(context.Context) (CollectionBaseline, error) { return BaselineFromStatus(before, *now), nil }
		m.VerifyCollection = func(context.Context, CollectionBaseline) bool { return verified }
		m.RunningVersion = func(context.Context) string { return PackageVersion(runner.candidate) }
		if err := m.Once(context.Background(), c, id, inventory); err != nil {
			t.Fatal(err)
		}
		if err := m.transition(c.plan.Plan.JobID, "installing", "", inventory.RunningVersion, inventory.InstalledPackage); err != nil {
			t.Fatal(err)
		}
		runner.installed = runner.candidate
		if err := m.Apply(context.Background()); err != nil {
			t.Fatal(err)
		}
		job, err := m.Store.Read()
		if err != nil {
			t.Fatal(err)
		}
		wantState, wantCheck := "failed", "failed"
		if verified {
			wantState, wantCheck = "succeeded", "verified"
		}
		if job.Last().State != wantState || job.Last().CollectionCheck != wantCheck || runner.installCount != 0 {
			t.Fatalf("reconcile skipped collection or reran RPM: %#v", job.Last())
		}
	}
}

func TestPostInstallDoesNotReportAnOldPackageSnapshotAsCurrent(t *testing.T) {
	m, c, id, inventory, runner, _ := fixture(t)
	if err := m.Once(context.Background(), c, id, inventory); err != nil {
		t.Fatal(err)
	}
	m.Healthy = func(context.Context, managed.UpdatePlan) bool { runner.installed.Release = "25.el9"; return true }
	if err := m.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	job, err := m.Store.Read()
	if err != nil {
		t.Fatal(err)
	}
	if job.Last().State != "failed" || job.Last().ErrorCode != "precondition_changed" || job.Last().InstalledPackage.Release != "25.el9" {
		t.Fatal("old installed package snapshot was reported as verified")
	}
}
