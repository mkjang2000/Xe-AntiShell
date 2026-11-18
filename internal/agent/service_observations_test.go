package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"xe-antishell/internal/capability"
	"xe-antishell/internal/config"
	"xe-antishell/internal/model"
	"xe-antishell/internal/storage"
)

const (
	observationService = "shop.service"
	protectedWriteRule = "service-protected-file-write"
	unexpectedTCPRule  = "service-unexpected-tcp-destination"
)

func shopObservationScope(cfg *config.Config) {
	cfg.Limits.ObservationHistoryMinutes = 60
	cfg.Detection.WebServices = []string{observationService}
	cfg.ServiceObservations = []config.ServiceObservationPolicy{observationScopeFixture(observationService)}
}

func observationScopeFixture(service string) config.ServiceObservationPolicy {
	return config.ServiceObservationPolicy{
		Service:                service,
		ProtectedDirs:          []string{"/srv/shop"},
		AllowedWriteDirs:       []string{"/srv/shop/uploads"},
		AllowedTCPDestinations: []config.TCPDestination{{CIDR: netip.MustParsePrefix("192.0.2.0/24"), Ports: []uint16{443}}},
	}
}

func TestServiceObservationFindingsFromTetragonSurviveAckAndExpiry(t *testing.T) {
	ctx := context.Background()
	s, store := newTestService(t, config.CollectorDisabled, shopObservationScope)
	defer store.Close()
	enableTimestampDelivery(t, store)
	s.status.Collector = "tetragon-json"
	start := time.Now().UTC().Add(-2 * time.Hour)
	s.lineage.Restore([]model.Process{{Key: "bootstrap-worker", PID: 840, Exe: sampleProbeExecutable, StartTime: start, OriginService: observationService}})
	written, zero, failed := int64(43), int64(0), int64(-13)
	cases := []struct {
		path, address string
		result        *int64
		ruleID        string
	}{
		{"/srv/shop/index.php", "", &written, protectedWriteRule},
		{"/srv/shop/uploads/photo.jpg", "", &written, ""},
		{"/srv/shop/app.php", "", &zero, ""},
		{"/srv/shop/app.php", "", nil, ""},
		{"", "198.51.100.12", &zero, unexpectedTCPRule},
		{"", "192.0.2.7", &zero, ""},
		{"", "198.51.100.12", &failed, ""},
		{"", "198.51.100.12", nil, ""},
	}
	want := make(map[string]string)
	for i, tc := range cases {
		source := sampleProbe{at: start.Add(time.Duration(i+1) * time.Second), start: start, identity: "shop-worker", pid: 840, path: tc.path, address: tc.address, result: tc.result}
		event := source.normalize(t, source.at)
		if err := s.processEvent(ctx, &event); err != nil {
			t.Fatal(err)
		}
		want[event.ID] = tc.ruleID
		// Re-delivery through the collector must not append a second finding or bundle.
		retry := source.normalize(t, source.at.Add(time.Minute))
		if err := s.processEvent(ctx, &retry); err != nil {
			t.Fatal(err)
		}
	}
	batch, err := store.DeliveryBatch(ctx, 64)
	if err != nil || len(batch.Records) != len(cases) {
		t.Fatalf("outbox records=%d want=%d err=%v", len(batch.Records), len(cases), err)
	}
	for _, record := range batch.Records {
		var bundle managed.EventBundle
		if err := json.Unmarshal(record.Payload, &bundle); err != nil {
			t.Fatal(err)
		}
		e := bundle.Event
		wanted, ok := want[e.ID]
		if !ok || record.Kind != managed.RecordKindEventBundle || record.ID != e.ID || e.Process.OriginService != observationService ||
			len(e.RawJSON)+len(e.Ancestors)+len(e.Process.Argv) != 0 {
			t.Fatalf("unexpected compact bundle: %+v", bundle)
		}
		if wanted == "" {
			if len(bundle.Findings) != 0 {
				t.Fatalf("ordinary observation produced %+v", bundle.Findings)
			}
			continue
		}
		if len(bundle.Findings) != 1 {
			t.Fatalf("expected %s for %s: %+v", wanted, e.ID, bundle.Findings)
		}
		f := bundle.Findings[0]
		if f.RuleID != wanted || !f.DetectionOnly || f.ResponseDecision != "detection_only" || f.RiskScore <= 0 || len(f.RiskFactors) == 0 ||
			len(f.EvidenceEventIDs) != 1 || f.EvidenceEventIDs[0] != e.ID || f.OriginService != observationService || f.ProcessKey != e.Process.Key {
			t.Fatalf("incomplete finding or evidence link: %+v", f)
		}
		if wanted == protectedWriteRule && (e.File == nil || e.File.Path != cases[0].path || e.File.ReturnValue == nil || *e.File.ReturnValue != written) {
			t.Fatalf("lost confirmed write in bundle: %+v", e.File)
		}
		if wanted == unexpectedTCPRule && (e.Network == nil || e.Network.DestinationAddress != "198.51.100.12" || e.Network.Outcome != "initiated") {
			t.Fatalf("lost TCP initiation in bundle: %+v", e.Network)
		}
		if saved, err := store.GetFinding(ctx, f.ID); err != nil || saved.RuleID != wanted || saved.ID != f.ID {
			t.Fatalf("local finding disagrees with outbox: %+v %v", saved, err)
		}
	}
	ack := managed.Ack{SpoolID: batch.SpoolID, Acknowledged: batch.Records[len(batch.Records)-1].Sequence}
	if err := store.Acknowledge(ctx, ack, batch); err != nil {
		t.Fatal(err)
	}
	if n, err := store.DeleteEventsBefore(ctx, time.Now().Add(-time.Hour), 64); err != nil || n != int64(len(cases)-2) {
		t.Fatalf("ordinary expiry: n=%d err=%v", n, err)
	}
	for id, wanted := range want {
		_, err := store.GetEvent(ctx, id)
		if (wanted == "" && !errors.Is(err, storage.ErrNotFound)) || (wanted != "" && err != nil) {
			t.Fatalf("evidence %s for %q after expiry: %v", id, wanted, err)
		}
	}
	catalog, err := s.Rules(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for id, sensor := range map[string]string{protectedWriteRule: capability.FileCapability, unexpectedTCPRule: capability.NetworkCapability} {
		var seen bool
		for _, rule := range catalog.Rules {
			if rule.ID == id && rule.Enabled && rule.Response == "detection_only" {
				for _, required := range rule.Sensors {
					if required.Name == sensor && required.State == "active" && required.VerifiedAt != nil {
						seen = true
					}
				}
			}
		}
		if !seen {
			t.Fatalf("missing active %s receipt for %s", sensor, id)
		}
	}
}

func TestServiceObservationRulesFollowSignedWebServiceScope(t *testing.T) {
	ctx := context.Background()
	s, store := newTestService(t, config.CollectorDisabled, func(cfg *config.Config) {
		shopObservationScope(cfg)
		cfg.Detection.Enabled = false
	})
	defer store.Close()
	state, policy, key := managedPolicyFixture(t)
	if err := store.SaveManagedState(ctx, state); err != nil {
		t.Fatal(err)
	}
	start := time.Now().UTC().Add(-time.Minute)
	s.lineage.Restore([]model.Process{{Key: "bootstrap-worker", PID: 841, Exe: sampleProbeExecutable, StartTime: start, OriginService: observationService}})
	zero := int64(0)
	// Local policy initially observes only. Keep every source record so its
	// original decision can be checked after the final managed revision.
	first := sampleProbe{at: start, start: start, identity: "scope-worker", pid: 841, webParent: true, address: "198.51.100.32", result: &zero}
	persist := func(source sampleProbe, received time.Time) string {
		t.Helper()
		e := source.normalize(t, received)
		if err := s.processEvent(ctx, &e); err != nil {
			t.Fatal(err)
		}
		if _, err := store.GetEvent(ctx, e.ID); err != nil {
			t.Fatalf("missing observed event %s: %v", e.ID, err)
		}
		return e.ID
	}
	persist(first, first.at)
	probes := []sampleProbe{first}
	for i, step := range []struct {
		services  []string
		enabled   bool
		wantCount int
	}{
		{[]string{observationService}, true, 1},
		{[]string{"other.service"}, true, 1},
		{[]string{observationService}, false, 1},
		{[]string{observationService}, true, 2},
	} {
		policy.Revision = uint64(i + 1)
		policy.Detection.WebServices = step.services
		policy.Detection.Enabled = step.enabled
		if step.enabled {
			policy.Response = managed.ResponsePolicy{Mode: "would_block", Action: "terminate", RiskThreshold: 70, MinConfidence: .75, RequiredCapabilities: []string{capability.ProcessExecCapability}}
		} else {
			policy.Response = managed.ResponsePolicy{Mode: "observe", Action: "none"}
		}
		if err := s.applyManagedPolicy(ctx, signRuntimePolicy(t, policy, key), state, time.Now(), false); err != nil {
			t.Fatalf("apply rev %d: %v", policy.Revision, err)
		}
		// The nginx parent keeps this operation observable even when the signed
		// service list removes the worker. The local scope must then be dormant.
		source := first
		source.at = start.Add(time.Duration(i+1) * time.Second)
		id := persist(source, source.at)
		probes = append(probes, source)
		got, err := store.ListFindings(ctx, storage.FindingFilter{Limit: 10})
		if err != nil || len(got) != step.wantCount {
			t.Fatalf("rev %d: findings=%d want=%d err=%v", policy.Revision, len(got), step.wantCount, err)
		}
		if i == 0 || i == 3 {
			if f := got[0]; f.RuleID != unexpectedTCPRule || f.PolicyRevision != policy.Revision || f.ResponseDecision != "detection_only" ||
				len(f.EvidenceEventIDs) != 1 || f.EvidenceEventIDs[0] != id {
				t.Fatalf("rev %d finding: %+v", policy.Revision, f)
			}
		}
	}

	for _, source := range probes {
		persist(source, time.Now().UTC())
	}
	got, err := store.ListFindings(ctx, storage.FindingFilter{Limit: 10})
	if err != nil || len(got) != 2 {
		t.Fatalf("policy replacement generated a retroactive finding: %+v %v", got, err)
	}
	bundles, _ := timestampBundles(t, store)
	if len(bundles) != len(probes) {
		t.Fatalf("policy change or retry duplicated outbox records: %d", len(bundles))
	}
	for _, b := range bundles {
		for _, f := range b.Findings {
			saved, err := store.GetFinding(ctx, f.ID)
			if err != nil || saved.PolicyRevision != f.PolicyRevision || saved.ResponseDecision != f.ResponseDecision {
				t.Fatalf("original decision changed after retry: sent %+v stored %+v err=%v", f, saved, err)
			}
		}
	}
}

// Verify the existing central binary receives each new finding from its own
// enrolled agent and returns the matching typed evidence via its operator API.
func verifyCentralServiceObservationFindings(t *testing.T, ctx context.Context, central *independentCentral, s *Service, previousACK uint64) {
	t.Helper()
	agent := s.config.Agent.ID
	unit := agent + "-web.service"
	start := time.Now().UTC().Add(-time.Minute)
	s.lineage.Restore([]model.Process{{Key: "bootstrap-integration-worker", PID: 842, Exe: sampleProbeExecutable, StartTime: start, OriginService: unit}})
	written, zero := int64(8), int64(0)
	const targetPath = "/srv/shop/app.php"
	const targetAddress = "198.51.100.9"
	file := sampleProbe{hostID: agent, at: start.Add(time.Second), start: start, identity: "integration-worker", pid: 842, path: targetPath, result: &written}
	tcp := file
	tcp.at, tcp.path, tcp.address, tcp.result = file.at.Add(time.Second), "", targetAddress, &zero
	expected := make(map[string]string)
	for _, probe := range []sampleProbe{file, tcp} {
		event := probe.normalize(t, time.Now().UTC())
		if err := s.Submit(ctx, event); err != nil {
			t.Fatalf("%s submit %s: %v", agent, event.Type, err)
		}
		ruleID := protectedWriteRule
		if event.Network != nil {
			ruleID = unexpectedTCPRule
		}
		expected[event.ID] = ruleID
	}
	awaitIndependentCentral(t, ctx, "ACK for file and TCP findings on "+agent, func() bool {
		status, err := s.ManagedStatus(ctx)
		return err == nil && status.Delivery.Pending == 0 && status.Delivery.Acknowledged == previousACK+2 && status.Delivery.LostRecords == 0
	})
	var rows []struct {
		AgentID string              `json:"agent_id"`
		ID      string              `json:"id"`
		Payload managed.EventBundle `json:"payload"`
	}
	if err := central.request(ctx, http.MethodGet, "/admin/history?kind=event_bundle&limit=2&agent_id="+agent, nil, &rows); err != nil || len(rows) != 2 {
		t.Fatalf("%s central service observation bundles: n=%d err=%v", agent, len(rows), err)
	}
	for _, row := range rows {
		bundle := row.Payload
		e := bundle.Event
		ruleID, ok := expected[row.ID]
		if !ok || row.AgentID != agent || e.ID != row.ID || e.HostID != agent || e.Process.OriginService != unit || len(bundle.Findings) != 1 {
			t.Fatalf("%s missing or duplicated observation: %s", agent, row.ID)
		}
		delete(expected, row.ID)
		f := bundle.Findings[0]
		if f.RuleID != ruleID || f.OriginService != unit || f.PolicyRevision != 1 || f.ProcessKey != e.Process.Key || !f.DetectionOnly ||
			f.ResponseDecision != "detection_only" || len(f.EvidenceEventIDs) != 1 || f.EvidenceEventIDs[0] != e.ID {
			t.Fatalf("%s lost service rule or evidence reference: %+v", agent, f)
		}
		if ruleID == protectedWriteRule && (e.File == nil || e.File.Path != targetPath || e.File.ReturnValue == nil || *e.File.ReturnValue != written) {
			t.Fatalf("%s central write evidence: %+v", agent, e.File)
		}
		if ruleID == unexpectedTCPRule && (e.Network == nil || e.Network.DestinationAddress != targetAddress || e.Network.DestinationPort != 443 || e.Network.Outcome != "initiated" || e.Network.ReturnValue == nil || *e.Network.ReturnValue != 0) {
			t.Fatalf("%s central TCP evidence: %+v", agent, e.Network)
		}
	}
	t.Logf("%s: central ACK %d, protected write and TCP initiation evidence verified", agent, previousACK+2)
}
