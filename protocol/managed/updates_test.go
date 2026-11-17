package managed

import (
	"crypto/ed25519"
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"
)

func updateFixture() UpdatePlan {
	now := time.Date(2026, 11, 17, 14, 0, 0, 0, time.UTC)
	return UpdatePlan{ProtocolVersion: UpdateProtocolVersion, JobID: "job-1", RolloutID: "rollout-1", AgentID: "agent-1", EnrollmentID: "enrollment-123456789", Revision: 3, IssuedAt: now, ExpiresAt: now.Add(15 * time.Minute),
		Release:         UpdateRelease{ID: "release-1", Package: RPMPackage{Name: "xe-antishell", Version: "0.1.0", Release: "23.el9", Arch: "x86_64"}, OSFamily: "rhel", OSMajor: "9", SHA256: strings.Repeat("a", 64), Size: 12345, CreatedAt: now.Add(-time.Hour)},
		ExpectedPackage: RPMPackage{Name: "xe-antishell", Version: "0.1.0", Release: "22.el9", Arch: "x86_64"}}
}

func TestUpdatePlanSignatureIdentityRevisionAndDomain(t *testing.T) {
	public, private, _ := GenerateSigningKey()
	trusted := map[string]ed25519.PublicKey{"key-1": public}
	plan := updateFixture()
	signed, err := SignUpdatePlan(plan, "key-1", private)
	if err != nil {
		t.Fatal(err)
	}
	verify := func(value SignedUpdatePlan, agent, enrollment string, revision uint64, now time.Time) error {
		_, err := VerifyUpdatePlan(value, trusted, agent, enrollment, revision, now)
		return err
	}
	if err := verify(signed, plan.AgentID, plan.EnrollmentID, plan.Revision, plan.IssuedAt); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, agent, enrollment string
		revision                uint64
		now                     time.Time
	}{
		{"other-agent", "agent-2", plan.EnrollmentID, 3, plan.IssuedAt},
		{"reenrolled", plan.AgentID, "enrollment-replaced", 3, plan.IssuedAt},
		{"rollback", plan.AgentID, plan.EnrollmentID, 4, plan.IssuedAt},
		{"expired", plan.AgentID, plan.EnrollmentID, 3, plan.ExpiresAt},
		{"future", plan.AgentID, plan.EnrollmentID, 3, plan.IssuedAt.Add(-2 * time.Minute)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if verify(signed, test.agent, test.enrollment, test.revision, test.now) == nil {
				t.Fatal("unsafe update plan accepted")
			}
		})
	}
	mutated := signed
	mutated.Plan.Release.SHA256 = strings.Repeat("b", 64)
	if verify(mutated, plan.AgentID, plan.EnrollmentID, 3, plan.IssuedAt) == nil {
		t.Fatal("artifact tamper accepted")
	}
	mutated = signed
	mutated.Signature, _ = signValue("policy", "key-1", plan, private, MaxUpdateBytes)
	if verify(mutated, plan.AgentID, plan.EnrollmentID, 3, plan.IssuedAt) == nil {
		t.Fatal("policy signature reused as update")
	}
}

func TestUpdateInstallAuthorizationBindsExactPlanAndShortValidity(t *testing.T) {
	public, private, _ := GenerateSigningKey()
	trusted := map[string]ed25519.PublicKey{"key-1": public}
	plan := updateFixture()
	digest, err := UpdatePlanDigest(plan)
	if err != nil {
		t.Fatal(err)
	}
	a := UpdateAuthorization{ProtocolVersion: 1, JobID: plan.JobID, AgentID: plan.AgentID, EnrollmentID: plan.EnrollmentID, Revision: plan.Revision, PlanSHA256: digest, IssuedAt: plan.IssuedAt, ExpiresAt: plan.IssuedAt.Add(2 * time.Minute)}
	signed, err := SignUpdateAuthorization(a, "key-1", private)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyUpdateAuthorization(signed, trusted, plan, plan.IssuedAt); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*UpdatePlan){
		func(p *UpdatePlan) { p.ExpectedPackage.Release = "21.el9" }, func(p *UpdatePlan) { p.JobID = "job-2" }, func(p *UpdatePlan) { p.Revision++ }, func(p *UpdatePlan) { p.EnrollmentID = "enrollment-replaced" },
	} {
		changed := plan
		mutate(&changed)
		if _, err := VerifyUpdateAuthorization(signed, trusted, changed, plan.IssuedAt); err == nil {
			t.Fatal("install lease accepted for different plan")
		}
	}
	if _, err := VerifyUpdateAuthorization(signed, trusted, plan, a.ExpiresAt); err == nil {
		t.Fatal("expired install lease accepted")
	}
	a.ExpiresAt = a.IssuedAt.Add(6 * time.Minute)
	if _, err := SignUpdateAuthorization(a, "key-1", private); err == nil {
		t.Fatal("long install lease accepted")
	}
	a.ExpiresAt = plan.ExpiresAt.Add(time.Minute)
	a.IssuedAt = plan.ExpiresAt.Add(-time.Minute)
	signed, err = SignUpdateAuthorization(a, "key-1", private)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyUpdateAuthorization(signed, trusted, plan, a.IssuedAt); err == nil {
		t.Fatal("install lease outlived plan")
	}
}

func TestUpdateReleaseAndPlanBounds(t *testing.T) {
	for _, mutate := range []func(*UpdatePlan){
		func(p *UpdatePlan) { p.Release.Size = MaxUpdateArtifactBytes + 1 }, func(p *UpdatePlan) { p.Release.Size = 0 },
		func(p *UpdatePlan) { p.Release.SHA256 = strings.Repeat("A", 64) }, func(p *UpdatePlan) { p.Release.OSMajor = "10" },
		func(p *UpdatePlan) { p.Release.Package.Name = "other-package" }, func(p *UpdatePlan) { p.Release.Package.Arch = "i686" },
		func(p *UpdatePlan) { p.Release.Package.Epoch = math.MaxUint64 }, func(p *UpdatePlan) { p.Release.Package.Release = "23.el9\nsecret" },
		func(p *UpdatePlan) { p.Revision = 0 }, func(p *UpdatePlan) { p.ExpiresAt = p.IssuedAt.Add(25 * time.Hour) },
	} {
		plan := updateFixture()
		mutate(&plan)
		if plan.Validate() == nil {
			t.Fatal("unbounded or incompatible update accepted")
		}
	}
	plan := updateFixture()
	body, _ := json.Marshal(plan)
	body = append(body[:len(body)-1], []byte(`,"command":"do-not-execute"}`)...)
	var decoded UpdatePlan
	if DecodeStrict(body, MaxUpdateBytes, &decoded) == nil {
		t.Fatal("arbitrary command field accepted")
	}
}

func TestUpdateReportsRequireFixedDiagnosticsAndObservedPackage(t *testing.T) {
	plan := updateFixture()
	report := UpdateReport{ProtocolVersion: 1, JobID: plan.JobID, EnrollmentID: plan.EnrollmentID, Revision: 3, Sequence: 1, State: "downloading", RunningVersion: "0.1.0-22.el9", ObservedAt: plan.IssuedAt}
	if err := report.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*UpdateReport){func(r *UpdateReport) { r.State = "succeeded" }, func(r *UpdateReport) { r.ErrorCode = "raw stderr SECRET" }, func(r *UpdateReport) { r.State = "failed" }, func(r *UpdateReport) { r.Sequence = 0 }, func(r *UpdateReport) { r.State = "queued" }} {
		copy := report
		mutate(&copy)
		if copy.Validate() == nil {
			t.Fatal("invalid report accepted")
		}
	}
	report.State = "succeeded"
	report.InstalledPackage = &plan.Release.Package
	if err := report.Validate(); err != nil {
		t.Fatal(err)
	}
	inventory := UpdateInventory{ProtocolVersion: 1, Supported: true, Enabled: true, OSFamily: "rhel", OSMajor: "9", Arch: "x86_64", InstalledPackage: &plan.ExpectedPackage, RunningVersion: "0.1.0-22.el9", ObservedAt: plan.IssuedAt}
	if err := inventory.Validate(); err != nil {
		t.Fatal(err)
	}
	inventory.InstalledPackage = nil
	if inventory.Validate() == nil {
		t.Fatal("incomplete update support accepted")
	}
}

func TestUpdateRPMVersionSyntaxAndEpochBuildIdentity(t *testing.T) {
	pack := updateFixture().Release.Package
	for _, bad := range []string{"0.1-beta", "0.1%macro", "0.1/escape", "0.1\nprivate"} {
		copy := pack
		copy.Version = bad
		if copy.Validate() == nil {
			t.Fatal("invalid RPM component accepted")
		}
	}
	pack.Version = "1.0~rc1^snapshot+2"
	pack.Epoch = 2
	if err := pack.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := pack.RunningVersion(); got != "2:1.0~rc1^snapshot+2-23.el9.x86_64" || !validBuildVersion(got) {
		t.Fatal("epoch/prerelease build identity was lost")
	}
}
