package agent

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"xe-antishell/internal/config"
)

func TestAgentConfigurationRetainsApprovedStateAcrossRejectionAndRestart(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	service, database := newTestService(t, config.CollectorDisabled, func(cfg *config.Config) {
		cfg.Limits.ObservationHistoryMinutes = 60
		cfg.AgentConfiguration.MaxObservationHistoryMinutes = 240
	})
	defer database.Close()
	enrolled, _, key := managedPolicyFixture(t)
	if err := database.SaveManagedState(ctx, enrolled); err != nil {
		t.Fatal(err)
	}
	apply := func(revision, base uint64, set managed.AgentConfigurationSet, inherit []string, approved bool) {
		t.Helper()
		config := managed.AgentConfiguration{SchemaVersion: managed.SchemaVersion, AgentID: enrolled.AgentID, EnrollmentID: enrolled.EnrollmentID,
			Revision: revision, BaseRevision: base, IssuedAt: now, ExpiresAt: now.Add(time.Minute),
			Set: set, Inherit: inherit, RetentionReductionApproved: approved}
		signed, err := managed.SignAgentConfiguration(config, enrolled.PolicyKeyID, key)
		if err != nil {
			t.Fatal(err)
		}
		service.applyAgentConfiguration(ctx, signed, enrolled, now)
	}
	witness := func() managed.AgentConfigurationReport {
		t.Helper()
		report, err := service.Capabilities(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var result managed.AgentConfigurationReport
		if err := json.Unmarshal([]byte(report.Capabilities[managed.AgentConfigurationCapability].Details["snapshot"]), &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	initial := managed.AgentConfigurationSet{
		Monitoring: &managed.AgentConfigurationMonitoring{SampleIntervalSeconds: 45},
		Retention:  &managed.AgentConfigurationRetention{ObservationHistoryMinutes: 120},
		LocalPanel: &managed.AgentConfigurationLocalPanel{Access: "block"},
	}
	apply(1, 0, initial, nil, false)
	applied := witness()
	panel, err := service.PanelAccess(ctx)
	if err != nil || panel.Access != "block" || panel.Generation == "" ||
		applied.Result != "applied" || applied.AppliedRevision != 1 ||
		applied.Effective.HeartbeatIntervalSeconds != 10 || applied.Effective.SampleIntervalSeconds != 45 ||
		!service.observationCutoff(now).Equal(now.Add(-2*time.Hour)) {
		t.Fatalf("first assignment not effective: report %#v, panel %#v, %v", applied, panel, err)
	}
	shorter := initial
	shorter.Retention = &managed.AgentConfigurationRetention{ObservationHistoryMinutes: 60}
	apply(2, 1, shorter, nil, false)
	rejected := witness()
	if rejected.Result != "rejected" || rejected.Error != "retention_reduction_not_approved" ||
		rejected.RequestedRevision != 2 || rejected.AppliedRevision != 1 || service.observationHistoryMinutes() != 120 {
		t.Fatalf("unconfirmed history reduction applied: %#v", rejected)
	}
	tooLong := initial
	tooLong.Retention = &managed.AgentConfigurationRetention{ObservationHistoryMinutes: 300}
	apply(3, 1, tooLong, nil, true)
	if report := witness(); report.Error != "local_retention_limit" || report.AppliedRevision != 1 {
		t.Fatalf("host cap did not hold: %#v", report)
	}
	apply(4, 1, shorter, nil, true)
	unchanged, _ := service.PanelAccess(ctx)
	if unchanged.Generation != panel.Generation || service.observationHistoryMinutes() != 60 {
		t.Fatalf("retention-only revision changed panel session generation: %#v", unchanged)
	}
	// Restoring verifies the durable decision at acceptance, even if the
	// assignment could no longer be newly accepted at today's clock.
	restarted, err := NewWithProcessSource(service.config, database, service.prober, staticProcessSource{})
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.restoreAgentConfiguration(ctx, enrolled); err != nil {
		t.Fatal(err)
	}
	restored, _ := restarted.PanelAccess(ctx)
	if restored != unchanged || restarted.approvedAgentConfiguration().Revision != 4 {
		t.Fatalf("restart lost the applied decision: %#v", restored)
	}
	open := shorter
	open.LocalPanel = nil
	apply(5, 4, open, []string{managed.AgentConfigPanelKey}, false)
	after, _ := service.PanelAccess(ctx)
	if after.Access != "allow" || after.Generation == unchanged.Generation {
		t.Fatalf("inheriting panel access reused old cookie generation: %#v", after)
	}
}
