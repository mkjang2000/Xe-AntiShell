package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"xe-antishell/internal/capability"
	"xe-antishell/internal/config"
	"xe-antishell/internal/model"
	"xe-antishell/internal/storage"
)

func TestManagedServiceObservationScopeSwitch(t *testing.T) {
	ctx := context.Background()
	svc, store := newTestService(t, config.CollectorDisabled, shopObservationScope)
	defer store.Close()
	enrollment, policy, key := managedPolicyFixture(t)
	policy.Detection.WebServices = []string{observationService}
	remote := []managed.ServiceObservationPolicy{{
		Service: observationService, ProtectedDirs: []string{"/srv/remote"}, AllowedWriteDirs: []string{"/srv/remote/cache"},
		AllowedTCPDestinations: []managed.TCPDestination{{CIDR: netip.MustParsePrefix("198.51.100.0/24")}},
	}}
	clear := []managed.ServiceObservationPolicy{}

	// Capability negotiation happens before a single file/TCP sensor receipt.
	svc.status.Collector = "tetragon-json"
	_, report := svc.runtimeSnapshot()
	engine := report.Capabilities[serviceObservationCapability]
	if engine.Implementation != "implemented" || engine.State != model.CapabilitySupported || engine.RuntimeState != "available" || engine.Details["contract"] != "1" || engine.VerifiedAt != nil {
		t.Fatalf("missing signed policy support: %+v", engine)
	}
	for _, sensor := range []string{capability.FileCapability, capability.NetworkCapability} {
		if r := report.Capabilities[sensor]; r.RuntimeState == "active" || r.VerifiedAt != nil {
			t.Fatalf("policy support produced a sensor receipt: %+v", r)
		}
	}

	start := time.Now().UTC().Add(-time.Minute)
	svc.lineage.Restore([]model.Process{{Key: "bootstrap", PID: 841, Exe: sampleProbeExecutable, StartTime: start, OriginService: observationService}})
	written, zero := int64(12), int64(0)
	probes := []sampleProbe{{path: "/srv/shop/index.php", result: &written}, {path: "/srv/remote/index.php", result: &written},
		{address: "192.0.2.5", result: &zero}, {address: "198.51.100.8", result: &zero}, {path: "/srv/remote/cache/item", result: &written}}
	localFindings := []string{protectedWriteRule, "", "", unexpectedTCPRule, ""}
	centralFindings := []string{"", protectedWriteRule, unexpectedTCPRule, "", ""}
	type expectation struct {
		rule     string
		revision uint64
	}
	want := map[string]expectation{}
	var retry sampleProbe
	for i, step := range []struct {
		scopes  *[]managed.ServiceObservationPolicy
		source  string
		enabled bool
		rules   []string
	}{
		{nil, "local", true, localFindings}, {&remote, "managed", true, centralFindings}, {&clear, "managed", false, make([]string, len(probes))}, {nil, "local", true, localFindings},
	} {
		policy.Revision = uint64(i + 1)
		policy.Detection.ServiceObservations = step.scopes
		signed := signRuntimePolicy(t, policy, key)
		for attempt := 0; attempt < 2; attempt++ {
			if err := svc.applyManagedPolicy(ctx, signed, enrollment, time.Now().UTC(), false); err != nil {
				t.Fatal(err)
			}
		}
		if i == 1 {
			invalid := signed
			invalid.Policy.Revision++
			invalid.Policy.Detection.ServiceObservations = &clear
			if err := svc.applyManagedPolicy(ctx, invalid, enrollment, time.Now().UTC(), false); err == nil {
				t.Fatal("accepted tampered scope")
			}
		}
		assertServiceScopeCatalog(t, svc, policy.Revision, step.source, step.enabled, step.enabled)
		for j, p := range probes {
			p.identity, p.pid, p.start = "scope-worker", 841, start
			p.at = start.Add(time.Duration(i*len(probes)+j+1) * time.Second)
			e := p.normalize(t, p.at)
			if err := svc.processEvent(ctx, &e); err != nil {
				t.Fatal(err)
			}
			if _, err := store.GetEvent(ctx, e.ID); err != nil {
				t.Fatal(err)
			}
			if rule := step.rules[j]; rule != "" {
				want[e.ID] = expectation{rule, policy.Revision}
			}
			if i == 0 && j == 0 {
				retry = p
			}
		}
		e := retry.normalize(t, time.Now().UTC())
		if err := svc.processEvent(ctx, &e); err != nil {
			t.Fatal(err)
		}
	}
	got, err := store.ListFindings(ctx, storage.FindingFilter{Limit: 100})
	if err != nil || len(got) != len(want) {
		t.Fatalf("got %d findings, want %d, err %v", len(got), len(want), err)
	}
	for _, f := range got {
		if len(f.EvidenceEventIDs) != 1 {
			t.Fatalf("unexpected evidence %+v", f)
		}
		evidence := f.EvidenceEventIDs[0]
		expected, ok := want[evidence]
		if !ok || f.RuleID != expected.rule || f.PolicyRevision != expected.revision || !f.DetectionOnly || f.OriginService != observationService {
			t.Fatalf("unexpected finding %+v for %+v", f, expected)
		}
		delete(want, evidence)
	}
}

func assertServiceScopeCatalog(t *testing.T, svc *Service, revision uint64, source string, file, tcp bool) {
	t.Helper()
	catalog, err := svc.Rules(context.Background())
	if err != nil || catalog.PolicyRevision != revision || catalog.PolicySource != "managed" || catalog.ServiceObservationSource != source {
		t.Fatalf("unexpected catalog revision or scope source: %+v %v", catalog, err)
	}
	required := map[string]bool{protectedWriteRule: file, unexpectedTCPRule: tcp}
	for _, r := range catalog.Rules {
		if want, ok := required[r.ID]; ok {
			if r.Enabled != want {
				t.Fatalf("%s enabled=%v, want %v", r.ID, r.Enabled, want)
			}
			delete(required, r.ID)
		}
	}
	if len(required) > 0 {
		t.Fatalf("rules missing from catalog: %v", required)
	}
	status, err := svc.Status(context.Background())
	if err != nil || status.CapabilityReport.Capabilities[serviceObservationCapability].Details["scope_source"] != source {
		t.Fatalf("capability and catalog scope source disagree: %v", err)
	}
}

func TestServiceObservationScopesRestoredAtStartup(t *testing.T) {
	ctx := context.Background()
	central := newEnrollmentCentralFixture(t)
	cfg, store, prober := newTestDependencies(t, config.CollectorDisabled, shopObservationScope)
	svc, err := NewWithProcessSource(cfg, store, prober, staticProcessSource{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.EnrollWithRecovery(ctx, central.server.URL, "agent-test", central.caPEM, "test-token", enrollmentRecoveryCode(t)); err != nil {
		t.Fatal(err)
	}
	state, err := store.ManagedState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	central.server.Close() // Restore on startup with the issuing server offline.
	policy := managed.DefaultPolicy(state.AgentID, state.EnrollmentID, 1, time.Now().UTC().Add(-time.Second))
	policy.Detection.WebServices = []string{observationService}
	clear := []managed.ServiceObservationPolicy{}
	files := []managed.ServiceObservationPolicy{{Service: observationService, ProtectedDirs: []string{"/srv/new"}}}
	for i, step := range []struct {
		scopes    *[]managed.ServiceObservationPolicy
		source    string
		file, tcp bool
	}{
		{nil, "local", true, true}, {&files, "managed", true, false}, {&clear, "managed", false, false},
	} {
		policy.Revision = uint64(i + 1)
		policy.Detection.ServiceObservations = step.scopes
		signed, err := managed.SignPolicy(policy, state.PolicyKeyID, central.policyKey)
		if err != nil {
			t.Fatal(err)
		}
		if err := svc.applyManagedPolicy(ctx, signed, state, time.Now().UTC(), false); err != nil {
			t.Fatal(err)
		}
		if i > 0 {
			shutdownService(t, svc)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		store, err = storage.Open(ctx, cfg.Agent.DatabasePath)
		if err != nil {
			t.Fatal(err)
		}
		svc, err = NewWithProcessSource(cfg, store, prober, staticProcessSource{})
		if err != nil {
			t.Fatal(err)
		}
		startService(t, svc)
		assertServiceScopeCatalog(t, svc, policy.Revision, step.source, step.file, step.tcp)
	}
	shutdownService(t, svc)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestServiceRuleExceptionExpiresAcrossOfflineRestartAndReplay(t *testing.T) {
	ctx := context.Background()
	c := newEnrollmentCentralFixture(t)
	cfg, store, prober := newTestDependencies(t, config.CollectorDisabled, shopObservationScope)
	svc, err := NewWithProcessSource(cfg, store, prober, staticProcessSource{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.EnrollWithRecovery(ctx, c.server.URL, "agent-test", c.caPEM, "test-token", enrollmentRecoveryCode(t)); err != nil {
		t.Fatal(err)
	}
	state, err := store.ManagedState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	end := now.Add(time.Minute)
	p := managed.DefaultPolicy(state.AgentID, state.EnrollmentID, 1, now)
	p.Detection.WebServices = []string{observationService}
	p.Detection.ServiceRuleControls = []managed.ServiceRuleControl{{Service: observationService, RuleID: managed.RuleWebDescendantShell, Mode: "suppress_until", Reason: "approved service update", ExpiresAt: &end}}
	signed, err := managed.SignPolicy(p, state.PolicyKeyID, c.policyKey)
	if err != nil {
		t.Fatal(err)
	}
	if err = svc.applyManagedPolicy(ctx, signed, state, now, false); err != nil {
		t.Fatal(err)
	}
	sample := model.Event{ID: "before", SourceEventID: "source-before", Type: "process.exec", Source: "replay", EventTime: now, IngestTime: now, BootID: "boot-test", HostID: state.AgentID, Process: model.Process{PID: 454, Exe: "/bin/sh", UID: 1000, EUID: 1000, OriginService: observationService, StartTime: now, ExecID: "sample"}}
	send := func(e model.Event, at time.Time) {
		t.Helper()
		if err := svc.processObservation(ctx, &e, 0, time.Time{}, at); err != nil {
			t.Fatal(err)
		}
	}
	send(sample, end.Add(-time.Nanosecond))
	c.server.Close()
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = storage.Open(ctx, cfg.Agent.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	svc, err = NewWithProcessSource(cfg, store, prober, staticProcessSource{})
	if err != nil {
		t.Fatal(err)
	}
	startService(t, svc)
	defer shutdownService(t, svc)
	send(sample, end)
	other := sample
	other.ID = "after"
	other.SourceEventID = "source-after"
	send(other, end)
	findings, err := store.ListFindings(ctx, storage.FindingFilter{Limit: 5})
	if err != nil || len(findings) != 1 || findings[0].EvidenceEventIDs[0] != "after" || findings[0].PolicyRevision != 1 {
		t.Fatalf("offline expiry or historical replay changed findings: %+v %v", findings, err)
	}
	batch, err := store.DeliveryBatch(ctx, 16)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, r := range batch.Records {
		if r.Kind == managed.RecordKindEventBundle {
			var b managed.EventBundle
			if err := json.Unmarshal(r.Payload, &b); err != nil {
				t.Fatal(err)
			}
			counts[r.ID] = len(b.Findings)
		}
	}
	if len(counts) != 2 || counts["before"] != 0 || counts["after"] != 1 {
		t.Fatalf("first delivery verdicts changed: %v", counts)
	}
}

func TestServiceRuleExceptionsRequireDirectAttributionThroughReplay(t *testing.T) {
	ctx := context.Background()
	s, store := newTestService(t, config.CollectorDisabled, func(cfg *config.Config) {
		shopObservationScope(cfg)
		cfg.Detection.ServiceRuleControls = []managed.ServiceRuleControl{
			{Service: observationService, RuleID: managed.RuleWebDescendantShell, Mode: "disabled"},
			{Service: observationService, RuleID: protectedWriteRule, Mode: "disabled"},
		}
	})
	defer store.Close()
	s.status.Collector = "tetragon-json"
	start := time.Now().UTC().Add(-time.Minute)
	parent := model.Process{Key: "ancestor", PID: 450, Exe: "/usr/sbin/nginx", OriginService: observationService, StartTime: start}
	worker := model.Process{Key: "known", PID: 841, Exe: sampleProbeExecutable, OriginService: observationService, StartTime: start}
	s.lineage.Restore([]model.Process{parent, worker})
	value := int64(8)
	write := sampleProbe{identity: "inferred", pid: 841, start: start, at: start.Add(time.Second), path: "/srv/shop/file", result: &value}.normalize(t, start.Add(2*time.Second))
	shell := model.Event{ID: "inferred-shell", Type: "process.exec", Source: "replay", BootID: "boot-test", EventTime: start.Add(time.Second), Process: model.Process{PID: 455, PPID: 450, ParentKey: parent.Key, Exe: "/bin/sh", UID: 1000, EUID: 1000, StartTime: start.Add(time.Second)}}
	for _, e := range []model.Event{shell, write} {
		if err := s.processEvent(ctx, &e); err != nil {
			t.Fatal(err)
		}
		stored, err := store.GetEvent(ctx, e.ID)
		if err != nil || stored.Process.OriginService != observationService || !slices.Contains(stored.MissingFields, model.DirectServiceEvidence) {
			t.Fatalf("missing attribution evidence: %+v %v", stored, err)
		}
		sample, err := json.Marshal(stored)
		if err != nil {
			t.Fatal(err)
		}
		cmp, err := CompareRulesAt(ctx, s.config, s.config, bytes.NewReader(sample), start)
		if err != nil {
			t.Fatal(err)
		}
		id := protectedWriteRule
		if e.Type == "process.exec" {
			id = managed.RuleWebDescendantShell
		}
		for _, r := range cmp.Rules {
			if r.ID == id && (r.Current != 1 || r.Candidate != 1) {
				t.Fatalf("exported inferred %s incorrectly suppressed: %+v", id, r)
			}
		}
	}
	s.processSource = staticProcessSource{origin: observationService}
	shell.ID = "direct-shell"
	shell.Process.PID++
	write = sampleProbe{identity: "inferred", pid: 841, start: start, at: start.Add(4 * time.Second), path: "/srv/shop/direct", result: &value}.normalize(t, start.Add(5*time.Second))
	for _, e := range []model.Event{shell, write} {
		if err := s.processEvent(ctx, &e); err != nil {
			t.Fatal(err)
		}
		if slices.Contains(e.MissingFields, model.DirectServiceEvidence) {
			t.Fatal("direct attribution was lost")
		}
	}
	got, err := store.ListFindings(ctx, storage.FindingFilter{Limit: 10})
	if err != nil || len(got) != 2 {
		t.Fatalf("want two inferred findings; got %+v, %v", got, err)
	}
}
