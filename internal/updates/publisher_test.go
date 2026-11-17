package updates

import (
	"context"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

func TestDeploymentAuthorizationCannotReplacePublisherTrust(t *testing.T) {
	for _, scenario := range []string{"unknown_publisher", "tampered_manifest", "deployment_key_as_publisher"} {
		t.Run(scenario, func(t *testing.T) {
			m, c, id, inventory, runner, _ := fixture(t)
			plan := c.plan.Plan
			switch scenario {
			case "unknown_publisher":
				plan.Release.Publisher, _ = managed.SignReleaseManifest(plan.Release.Publisher.Manifest, "unknown-publisher", c.publisherPrivate)
			case "tampered_manifest":
				plan.Release.SHA256 = strings.Repeat("a", 64)
				plan.Release.Publisher.Manifest.SHA256 = plan.Release.SHA256
			case "deployment_key_as_publisher":
				plan.Release.Publisher, _ = managed.SignReleaseManifest(plan.Release.Publisher.Manifest, "publisher", c.private)
			}
			// A compromised deployment key can still produce a valid plan signature.
			signed, err := managed.SignUpdatePlan(plan, "key", c.private)
			if err != nil {
				t.Fatal(err)
			}
			c.plan = &signed
			if err := m.Once(context.Background(), c, id, inventory); err == nil || err.Error() != "signature_invalid" {
				t.Fatalf("publisher bypass accepted: %v", err)
			}
			if c.claims != 0 || runner.installCount != 0 || len(runner.commands) != 0 {
				t.Fatal("untrusted release reached package processing")
			}
			job, err := m.Store.Read()
			if err != nil || job != nil {
				t.Fatal("untrusted publisher was committed as an accepted job")
			}
		})
	}
}

func TestHelperIndependentlyRejectsDeploymentKeyForgedPublisher(t *testing.T) {
	m, c, id, inventory, runner, now := fixture(t)
	if err := m.Once(context.Background(), c, id, inventory); err != nil {
		t.Fatal(err)
	}
	if err := m.Store.Change(func(job *Job) (*Job, error) {
		plan := job.Plan.Plan
		plan.Release.Publisher, _ = managed.SignReleaseManifest(plan.Release.Publisher.Manifest, "publisher", c.private)
		job.Plan, _ = managed.SignUpdatePlan(plan, "key", c.private)
		digest, _ := managed.UpdatePlanDigest(plan)
		authorization, _ := managed.SignUpdateAuthorization(managed.UpdateAuthorization{ProtocolVersion: managed.UpdateProtocolVersion, JobID: plan.JobID, AgentID: plan.AgentID, EnrollmentID: plan.EnrollmentID, Revision: plan.Revision, PlanSHA256: digest, IssuedAt: *now, ExpiresAt: now.Add(time.Minute)}, "key", c.private)
		job.Authorization = &authorization
		return job, nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := m.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	job, _ := m.Store.Read()
	if runner.installCount != 0 || job.Last().ErrorCode != "signature_invalid" {
		t.Fatal("helper accepted central-only release authorization")
	}
}

func TestPublisherVerificationRemainsAtFinalRPMGate(t *testing.T) {
	m, c, id, inventory, runner, _ := fixture(t)
	if err := m.Once(context.Background(), c, id, inventory); err != nil {
		t.Fatal(err)
	}
	runner.beforeTest = func() { m.PublisherKeys = map[string]ed25519.PublicKey{} }
	if err := m.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	job, _ := m.Store.Read()
	if runner.installCount != 0 || job.Last().ErrorCode != "signature_invalid" {
		t.Fatal("publisher was not reverified before RPM execution")
	}
}
