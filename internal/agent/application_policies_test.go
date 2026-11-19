package agent

import (
	"context"
	"fmt"
	"testing"
	"time"

	contract "github.com/mkjang2000/Xe-AntiShell/protocol/integrity"
	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"xe-antishell/internal/capability"
	"xe-antishell/internal/config"
	"xe-antishell/internal/model"
	"xe-antishell/internal/response"
)

// A fixture independently maps live PIDs to units. Input OriginService may be
// untrusted, inherited, or stale.
type applicationProcessFixture struct {
	staticProcessSource
	units map[int]string
}

func (p applicationProcessFixture) SystemService(_ context.Context, event model.Event) (string, error) {
	return p.units[event.Process.PID], nil
}

func testApplication(unit, id, mode string) managed.ApplicationPolicy {
	a := managed.ApplicationPolicy{Service: unit, PolicyID: id, PolicyVersion: 3,
		Detection: managed.DetectionPolicy{Enabled: true, WebServices: []string{unit}, Shells: []string{"bash"}},
		Response:  managed.ResponsePolicy{Mode: mode, Action: "none"},
	}
	if mode != "observe" {
		a.Response = managed.ResponsePolicy{Mode: mode, Action: "terminate", RiskThreshold: 1, MinConfidence: .1, RequiredCapabilities: []string{capability.ProcessExecCapability}}
	}
	return a
}

func applicationExec(pid int, unit string) model.Event {
	now := time.Now().UTC()
	id := fmt.Sprintf("exec-%d", pid)
	return model.Event{ID: id, SourceEventID: id, Source: "tetragon", Type: "process.exec", EventTime: now, IngestTime: now, BootID: "boot-test",
		Process: model.Process{PID: pid, Exe: "/bin/bash", PPID: 1, ParentKey: "web-worker", ExecID: id, StartTime: now.Add(-time.Minute), UID: 1000, EUID: 1000, OriginService: unit, LineageConfidence: model.LineageVerified}}
}

func TestApplicationPoliciesScopeDetectionAndKeepGlobalPrivilege(t *testing.T) {
	ctx := context.Background()
	s, store := newTestService(t, config.CollectorDisabled, func(c *config.Config) {
		c.Collector.Tetragon.OnlyDetectionOrigins = true
	})
	defer store.Close()
	s.status.Collector = "tetragon-json"
	s.report.Capabilities = map[string]model.Capability{
		capability.ProcessExecCapability: {Name: capability.ProcessExecCapability, State: model.CapabilitySupported},
	}
	const nginx, pm2 = "nginx.service", "pm2-app.service"
	s.processSource = applicationProcessFixture{units: map[int]string{101: nginx, 102: pm2, 103: nginx, 104: pm2, 105: nginx, 106: pm2}}
	enrollment, policy, key := managedPolicyFixture(t)
	policy.Detection.WebServices, policy.Detection.WebExecutables = []string{nginx}, nil
	policy.Detection.PrivilegeRules, policy.Detection.RootExecAlerts = true, "all"
	policy.Applications = []managed.ApplicationPolicy{testApplication(nginx, "web", "would_block"), testApplication(pm2, "deployment", "observe")}
	signed := signRuntimePolicy(t, policy, key)
	if err := s.applyManagedPolicy(ctx, signed, enrollment, time.Now(), false); err != nil {
		t.Fatal(err)
	}
	sum, err := contract.PolicyDigest(signed)
	if err != nil || sum == "" || s.managedRuntime.status.Policy.PolicySHA256 != sum {
		t.Fatal("active digest does not identify the committed signed policy")
	}
	_, report := s.runtimeSnapshot()
	c := report.Capabilities[managed.ApplicationPoliciesCapability]
	if c.Implementation != "implemented" || c.RuntimeState != "available" || c.Details["contract"] != "1" || c.VerifiedAt != nil {
		t.Fatalf("capability = %+v", c)
	}
	for _, tt := range []struct {
		pid                        int
		unit, wantID, wantResponse string
		missing                    string
	}{
		{101, nginx, "web", "would_block", ""},
		{102, pm2, "deployment", "observe", ""},
		{103, nginx, "", "observe", model.DirectServiceEvidence},
		{104, nginx, "", "observe", ""},           // live PID now belongs to PM2
		{105, "NGINX.service", "", "observe", ""}, // historical web matcher is case-insensitive
		{106, nginx, "", "observe", "process.exec_id"},
	} {
		event := applicationExec(tt.pid, tt.unit)
		if tt.missing != "" {
			event.MissingFields = []string{tt.missing}
		}
		if err := s.processEvent(ctx, &event); err != nil {
			t.Fatal(err)
		}
		fs, err := s.ListFindings(ctx, 20)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, f := range fs {
			if len(f.EvidenceEventIDs) != 1 || f.EvidenceEventIDs[0] != event.ID {
				continue
			}
			found = true
			if f.ApplicationPolicyID != tt.wantID || f.ResponseDecision != tt.wantResponse || f.PolicyRevision != 1 ||
				(tt.wantID != "" && (f.ApplicationService != tt.unit || f.ApplicationPolicyVersion != 3)) {
				t.Fatalf("PID %d: unexpected decision %+v", tt.pid, f)
			}
		}
		if !found {
			t.Fatalf("PID %d: expected a retained finding", tt.pid)
		}
	}
	// A matched application's disabled detector leaves global root detections
	// in place. They carry the host revision and keep their detection-only gate.
	policy.Revision++
	policy.Applications[1].Detection.Enabled = false
	if err := s.applyManagedPolicy(ctx, signRuntimePolicy(t, policy, key), enrollment, time.Now(), false); err != nil {
		t.Fatal(err)
	}
	root := applicationExec(102, pm2)
	root.ID, root.SourceEventID, root.Process.ExecID = "root-exec", "root-exec", "root-exec"
	root.Process.EUID = 0
	if err := s.processEvent(ctx, &root); err != nil {
		t.Fatal(err)
	}
	fs, err := s.ListFindings(ctx, 1)
	if err != nil || len(fs) != 1 || fs[0].RuleID != managed.RulePrivilegeRootExecution || fs[0].ApplicationPolicyID != "" || fs[0].ResponseDecision != "detection_only" {
		t.Fatalf("host privilege finding lost or overridden: %+v, %v", fs, err)
	}
	policy.Revision++
	policy.Applications = nil
	if err := s.applyManagedPolicy(ctx, signRuntimePolicy(t, policy, key), enrollment, time.Now(), false); err != nil || s.managedRuntime.status.Policy.PolicySHA256 != "" {
		t.Fatalf("return to legacy status failed: %v", err)
	}
}

func TestApplicationPoliciesRejectWholeRevisionOnHostMismatch(t *testing.T) {
	ctx := context.Background()
	s, store := newTestService(t, config.CollectorDisabled, func(c *config.Config) { c.Collector.Tetragon.IncludeExecutables = []string{"bash"} })
	defer store.Close()
	enrollment, policy, key := managedPolicyFixture(t)
	policy.Detection.Shells = []string{"bash"}
	policy.Applications = []managed.ApplicationPolicy{testApplication("nginx.service", "web", "would_block"), testApplication("pm2-app.service", "deployment", "observe")}
	if err := s.applyManagedPolicy(ctx, signRuntimePolicy(t, policy, key), enrollment, time.Now(), false); err != nil {
		t.Fatal(err)
	}
	old := s.detectionState.Load()
	policy.Revision++
	for _, change := range []func(*managed.ApplicationPolicy){
		func(a *managed.ApplicationPolicy) { *a = testApplication(a.Service, a.PolicyID, "enforce") },
		func(a *managed.ApplicationPolicy) { a.Detection.Shells = []string{"other"} },
		func(a *managed.ApplicationPolicy) { a.Detection.ExtendedProcessRules = true },
	} {
		candidate := policy
		candidate.Applications = append([]managed.ApplicationPolicy(nil), policy.Applications...)
		change(&candidate.Applications[1])
		if err := s.applyManagedPolicy(ctx, signRuntimePolicy(t, candidate, key), enrollment, time.Now(), false); err == nil {
			t.Fatal("accepted a partially supported application policy")
		}
		stored, err := store.Policy(ctx)
		if err != nil || stored.Policy.Revision != 1 || s.detectionState.Load() != old {
			t.Fatalf("prior active revision changed, stored=%d err=%v", stored.Policy.Revision, err)
		}
	}
}

func TestApplicationEnforcementRechecksPendingFindingUnderCurrentPolicy(t *testing.T) {
	if response.Capability(true).State != model.CapabilitySupported {
		t.Skip("host lacks pidfd support")
	}
	ctx := context.Background()
	s, store := newTestService(t, config.CollectorDisabled, func(c *config.Config) { c.Response.AllowTerminate = true })
	defer store.Close()
	const unit = "nginx.service"
	s.processSource = staticProcessSource{origin: unit}
	enrollment, policy, key := managedPolicyFixture(t)
	policy.Applications = []managed.ApplicationPolicy{testApplication(unit, "web", "enforce")}
	if err := s.applyManagedPolicy(ctx, signRuntimePolicy(t, policy, key), enrollment, time.Now(), false); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	s.status.Collector = "tetragon-json"
	s.report.Capabilities = map[string]model.Capability{
		capability.ProcessExecCapability: {State: model.CapabilitySupported}, capability.ProcessLineageCapability: {State: model.CapabilitySupported},
	}
	s.runtimeEvidence = map[string]sourceRuntimeEvidence{"tetragon": {ExecAt: now, LineageAt: now}}
	original := s.detectionState.Load()
	event := applicationExec(421013, unit)
	app := s.applicationForEvent(ctx, event, original)
	if app == nil {
		t.Fatal("expected direct system service selection")
	}
	fs := s.evaluateObservation(event, original, app, now)
	if len(fs) != 1 || fs[0].ResponseDecision != "terminate_pending" {
		t.Fatalf("verified scope failed to produce the pending decision: %+v", fs)
	}
	policy.Revision++
	policy.Applications[0] = testApplication(unit, "now-observe", "observe")
	if err := s.applyManagedPolicy(ctx, signRuntimePolicy(t, policy, key), enrollment, now, false); err != nil {
		t.Fatal(err)
	}
	// Event arrived during the prior revision, and is committed after it was
	// replaced. A refusal must occur before any pidfd claim is created.
	if err := s.processCapturedObservation(ctx, &event, 0, time.Time{}, time.Now(), original); err != nil {
		t.Fatal(err)
	}
	saved, err := store.GetFinding(ctx, fs[0].ID)
	if err != nil || saved.ResponseDecision != "refused" || saved.PolicyRevision != 1 || saved.ApplicationPolicyID != "web" {
		t.Fatalf("stale decision permitted or original provenance lost: %+v %v", saved, err)
	}
	claimed, err := store.ClaimResponse(ctx, saved.ID, event.ID)
	if err != nil || !claimed {
		t.Fatalf("obsolete policy already claimed the response: %v %v", claimed, err)
	}
}

func TestApplicationExtendedFindingsAndExpiredPoliciesStayNonActing(t *testing.T) {
	ctx := context.Background()
	s, store := newTestService(t, config.CollectorDisabled, nil)
	defer store.Close()
	const unit = "nginx.service"
	s.processSource = staticProcessSource{origin: unit}
	enrollment, policy, key := managedPolicyFixture(t)
	app := testApplication(unit, "web", "would_block")
	app.Detection.ExtendedProcessRules = true
	policy.Applications = []managed.ApplicationPolicy{app}
	if err := s.applyManagedPolicy(ctx, signRuntimePolicy(t, policy, key), enrollment, time.Now(), false); err != nil {
		t.Fatal(err)
	}
	event := applicationExec(123, unit)
	state := s.detectionState.Load()
	fs := s.evaluateObservation(event, state, s.applicationForEvent(ctx, event, state), time.Now())
	if len(fs) != 1 || !fs[0].DetectionOnly || fs[0].ResponseDecision != "detection_only" || fs[0].ApplicationService != unit {
		t.Fatalf("extended detection could act: %+v", fs)
	}
	policy.Revision++
	policy.Applications[0].Detection.ExtendedProcessRules = false
	signed := signRuntimePolicy(t, policy, key)
	if err := s.applyManagedPolicy(ctx, signed, enrollment, time.Now(), false); err != nil {
		t.Fatal(err)
	}
	expired := policy.ExpiresAt.Add(time.Second)
	s.refreshPolicyExpiry(expired)
	for _, restore := range []bool{false, true} {
		if restore {
			if err := s.applyManagedPolicy(ctx, signed, enrollment, expired, true); err != nil {
				t.Fatal(err)
			}
		}
		state = s.detectionState.Load()
		fs = s.evaluateObservation(event, state, s.applicationForEvent(ctx, event, state), time.Now())
		if !state.expired || len(fs) != 1 || fs[0].ResponseDecision != "observe" || fs[0].ApplicationPolicyID != "web" || s.managedRuntime.status.Policy.Result != "stale" {
			t.Fatalf("expired app revived or lost detection (restore=%v): %+v", restore, fs)
		}
	}
}
