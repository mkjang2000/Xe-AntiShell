package agent

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"xe-antishell/internal/capability"
	"xe-antishell/internal/config"
	"xe-antishell/internal/managed"
	"xe-antishell/internal/model"
	"xe-antishell/internal/storage"
)

func managedPolicyFixture(t *testing.T) (storage.ManagedState, managed.Policy, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := managed.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	state := storage.ManagedState{AgentID: "agent-test", EnrollmentID: "enrollment-test", KeyPEM: "test-only", PolicyKeyID: "policy-key", PolicyPublicKey: managed.EncodePublicKey(public)}
	return state, managed.DefaultPolicy(state.AgentID, state.EnrollmentID, 1, time.Now().UTC().Add(-time.Second)), private
}

func signRuntimePolicy(t *testing.T, policy managed.Policy, key ed25519.PrivateKey) managed.SignedPolicy {
	t.Helper()
	signed, err := managed.SignPolicy(policy, "policy-key", key)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func TestManagedPolicyRejectsInvalidReplacement(t *testing.T) {
	service, store := newTestService(t, config.CollectorDisabled, nil)
	defer store.Close()
	state, policy, key := managedPolicyFixture(t)
	ctx := context.Background()
	if err := service.applyManagedPolicy(ctx, signRuntimePolicy(t, policy, key), state, time.Now(), false); err != nil {
		t.Fatal(err)
	}
	approved := service.detectionState.Load()
	tampered := signRuntimePolicy(t, policy, key)
	tampered.Policy.Detection.Enabled = false
	if err := service.applyManagedPolicy(ctx, tampered, state, time.Now(), false); err == nil {
		t.Fatal("accepted unsigned modification")
	}
	conflict := policy
	conflict.Detection.AllowedPairs = []string{"httpd:bash"}
	if err := service.applyManagedPolicy(ctx, signRuntimePolicy(t, conflict, key), state, time.Now(), false); err == nil {
		t.Fatal("accepted conflicting equal revision")
	}
	if service.detectionState.Load() != approved {
		t.Fatal("rejected policy changed active detector")
	}
	enforcement := policy
	enforcement.Revision = 2
	enforcement.Response = managed.ResponsePolicy{Mode: "enforce", Action: "terminate", RiskThreshold: 90, MinConfidence: .95, RequiredCapabilities: []string{capability.ProcessExecCapability}}
	if err := service.applyManagedPolicy(ctx, signRuntimePolicy(t, enforcement, key), state, time.Now(), false); err == nil {
		t.Fatal("enforcement accepted without host-local opt-in")
	}
	stored, err := store.Policy(ctx)
	if err != nil || stored.Policy.Revision != 1 {
		t.Fatalf("approved durable policy changed: %v %#v", err, stored)
	}
	if service.config.Detection.Enabled != config.Default().Detection.Enabled {
		t.Fatal("managed policy modified protected local config")
	}
}

func TestManagedPolicyExpiryRetainsDetectionAndDisablesResponse(t *testing.T) {
	service, store := newTestService(t, config.CollectorDisabled, nil)
	defer store.Close()
	state, policy, key := managedPolicyFixture(t)
	policy.Detection.WebServices = []string{"protected-test.service"}
	policy.Response = managed.ResponsePolicy{Mode: "would_block", Action: "terminate", RiskThreshold: 90, MinConfidence: .9, RequiredCapabilities: []string{capability.ProcessExecCapability}}
	if err := service.applyManagedPolicy(context.Background(), signRuntimePolicy(t, policy, key), state, time.Now(), false); err != nil {
		t.Fatal(err)
	}
	service.refreshPolicyExpiry(policy.ExpiresAt)
	active := service.detectionState.Load()
	if !active.enabled || active.policy.Response.Mode != "observe" || active.policy.Detection.WebServices[0] != "protected-test.service" {
		t.Fatalf("unsafe expiry transition: %#v", active.policy)
	}
	if service.managedRuntime.status.Policy.Result != "stale" {
		t.Fatal("expiry not reported")
	}
	// A restart authenticates the same stale policy and preserves its scope.
	if err := service.applyManagedPolicy(context.Background(), signRuntimePolicy(t, policy, key), state, policy.ExpiresAt.Add(time.Hour), true); err != nil {
		t.Fatal(err)
	}
}

func TestManagedWouldBlockRequiresIndependentRiskAndLiveCapabilities(t *testing.T) {
	service, store := newTestService(t, config.CollectorDisabled, nil)
	defer store.Close()
	_, policy, _ := managedPolicyFixture(t)
	policy.Response = managed.ResponsePolicy{Mode: "would_block", Action: "terminate", RiskThreshold: 90, MinConfidence: .9, RequiredCapabilities: []string{capability.ProcessExecCapability}}
	for _, test := range []struct {
		severity   string
		confidence float64
		want       string
	}{{"high", .99, "below_threshold"}, {"critical", .75, "below_threshold"}, {"critical", .95, "insufficient_capability"}} {
		findings := []model.Finding{{Severity: test.severity, Confidence: test.confidence}}
		service.applyResponseDecisions(findings, &policy)
		if findings[0].ResponseDecision != test.want {
			t.Fatalf("%+v: %#v", test, findings[0])
		}
	}
	now := time.Now().UTC()
	service.status = model.AgentStatus{Collector: "audit-dispatcher", Mode: model.AgentModeDegraded, Health: model.HealthDegraded}
	service.report.Capabilities = map[string]model.Capability{capability.ProcessExecCapability: {Name: capability.ProcessExecCapability, State: model.CapabilityLimited}}
	service.runtimeEvidence = map[string]sourceRuntimeEvidence{"audit": {ExecAt: now}}
	findings := []model.Finding{{Severity: "critical", Confidence: .95}}
	service.applyResponseDecisions(findings, &policy)
	if findings[0].ResponseDecision != "would_block" || findings[0].RiskScore != 95 || findings[0].Confidence != .95 {
		t.Fatalf("risk/confidence gates changed: %#v", findings[0])
	}
}

func TestManagedObservationPersistsBundleAndIdempotentDelivery(t *testing.T) {
	service, store := newTestService(t, config.CollectorDisabled, func(cfg *config.Config) { cfg.Detection.WebServices = []string{"test-web.service"} })
	defer store.Close()
	state, _, _ := managedPolicyFixture(t)
	ctx := context.Background()
	if err := store.SaveManagedState(ctx, state); err != nil {
		t.Fatal(err)
	}
	event := model.Event{ID: "event-managed", Type: "process.exec", Source: "test", BootID: "boot-test", EventTime: time.Now().UTC(), Process: model.Process{PID: 777, Exe: "/bin/bash", EUID: 1000, OriginService: "test-web.service"}}
	if err := service.processEvent(ctx, &event); err != nil {
		t.Fatal(err)
	}
	if err := service.processEvent(ctx, &event); err != nil {
		t.Fatal(err)
	}
	batch, err := store.DeliveryBatch(ctx, 64)
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.Records) != 1 || batch.Records[0].Sequence != 1 {
		t.Fatalf("duplicate observation changed delivery identity: %#v", batch)
	}
	var bundle managed.EventBundle
	if err := json.Unmarshal(batch.Records[0].Payload, &bundle); err != nil {
		t.Fatal(err)
	}
	if bundle.Event.ID != event.ID || len(bundle.Findings) != 1 || bundle.Findings[0].EvidenceEventIDs[0] != event.ID {
		t.Fatalf("evidence and findings not delivered atomically: %#v", bundle)
	}
}

func TestManagedDetectorReplacementUsesImmutableSnapshots(t *testing.T) {
	service, store := newTestService(t, config.CollectorDisabled, nil)
	defer store.Close()
	state, policy, key := managedPolicyFixture(t)
	var wait sync.WaitGroup
	wait.Add(1)
	go func() {
		defer wait.Done()
		for index := 0; index < 1000; index++ {
			snapshot := service.detectionState.Load()
			_ = snapshot.engine.Evaluate(model.Event{}, service.lineage)
			_ = service.currentMonitoring()
		}
	}()
	for revision := uint64(1); revision < 8; revision++ {
		policy.Revision = revision
		if err := service.applyManagedPolicy(context.Background(), signRuntimePolicy(t, policy, key), state, time.Now(), false); err != nil {
			t.Fatal(err)
		}
	}
	wait.Wait()
}

func TestManagedHeartbeatSuccessPreservesDeliveryFailure(t *testing.T) {
	service, store := newTestService(t, config.CollectorDisabled, nil)
	defer store.Close()
	const deliveryFailure = "central event delivery failed; records retained for retry"
	service.managedError("delivery", deliveryFailure)
	service.managedError("heartbeat", "central heartbeat failed")
	// Successful heartbeat and policy polling each clear only their own error.
	service.managedContact()
	service.managedError("heartbeat", "")
	service.managedContact()
	service.managedError("policy", "")
	status, err := service.ManagedStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.LastError != deliveryFailure || status.LastContactAt == nil {
		t.Fatalf("successful heartbeat/policy hid blocked delivery: %#v", status)
	}
	service.managedError("delivery", "")
	status, err = service.ManagedStatus(context.Background())
	if err != nil || status.LastError != "" {
		t.Fatalf("successful delivery did not clear its error: %#v %v", status, err)
	}
}

func TestManagedErrorsAggregateAndRecoverIndependently(t *testing.T) {
	service, store := newTestService(t, config.CollectorDisabled, nil)
	defer store.Close()
	service.managedError("policy", "central policy polling failed")
	service.managedError("heartbeat", "central heartbeat failed")
	service.managedContact()
	status, err := service.ManagedStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.LastError != "central heartbeat failed; central policy polling failed" {
		t.Fatalf("errors missing or ordered unpredictably: %q", status.LastError)
	}
	service.managedError("heartbeat", "")
	status, err = service.ManagedStatus(context.Background())
	if err != nil || status.LastError != "central policy polling failed" {
		t.Fatalf("heartbeat recovery cleared another operation: %#v %v", status, err)
	}
	service.managedError("policy", "")
	status, err = service.ManagedStatus(context.Background())
	if err != nil || status.LastError != "" {
		t.Fatalf("recovered errors were retained: %#v %v", status, err)
	}
}
