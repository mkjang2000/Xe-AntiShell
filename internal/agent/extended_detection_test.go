package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"xe-antishell/internal/config"
	"xe-antishell/internal/managed"
	"xe-antishell/internal/model"
	"xe-antishell/internal/storage"
)

func TestExtendedProcessDetectionScenarioMatrix(t *testing.T) {
	for _, test := range []struct {
		name, source, exe, origin, rule string
		argv, missing, redacted         []string
		score                           int
	}{
		{name: "web downloader without shell", source: "tetragon", exe: "/usr/bin/curl", origin: "example-web.service", rule: "web-descendant-download-tool", score: 60},
		{name: "web reconnaissance without shell", source: "tetragon", exe: "/usr/bin/id", origin: "example-web.service", rule: "web-descendant-recon-tool", score: 45},
		{name: "web connection utility", source: "audit", exe: "/usr/bin/socat", origin: "example-web.service", rule: "web-descendant-connection-tool", score: 70},
		{name: "web temporary executable", source: "tetragon", exe: "/tmp/uploaded-helper", origin: "example-web.service", rule: "web-descendant-temporary-executable", score: 65},
		{name: "web inline interpreter", source: "audit", exe: "/usr/bin/python3", origin: "example-web.service", argv: []string{"python3", "-c", "pass"}, rule: "web-descendant-inline-interpreter", score: 70},
		{name: "existing shell category", source: "tetragon", exe: "/bin/sh", origin: "example-web.service", rule: "web-descendant-shell", score: 85},
		{name: "normal application worker", source: "audit", exe: "/usr/bin/python3", origin: "example-web.service", argv: []string{"python3", "worker.py", "-c", "argument"}},
		{name: "normal node worker", source: "audit", exe: "/usr/bin/node", origin: "example-web.service", argv: []string{"node", "worker.js"}},
		{name: "unrelated admin download", source: "tetragon", exe: "/usr/bin/curl", origin: "sshd.service"},
		{name: "unrelated deployment shell", source: "audit", exe: "/bin/sh", origin: "deploy.service"},
		{name: "unrelated temporary execution", source: "tetragon", exe: "/tmp/helper", origin: "deploy.service"},
		{name: "temporary directory boundary", source: "tetragon", exe: "/tmp-backup/helper", origin: "example-web.service"},
		{name: "tool name boundary", source: "tetragon", exe: "/usr/bin/curl-helper", origin: "example-web.service"},
		{name: "tetragon never reconstructs exact argv", source: "tetragon", exe: "/usr/bin/python3", origin: "example-web.service", argv: []string{"python3", "-c", "pass"}, missing: []string{"process.argv_exact"}},
		{name: "partial audit argv", source: "audit", exe: "/usr/bin/python3", origin: "example-web.service", argv: []string{"python3", "-c", "pass"}, missing: []string{"process.argv_exact"}},
		{name: "redacted argv cannot prove inline code", source: "audit", exe: "/usr/bin/python3", origin: "example-web.service", argv: []string{"python3", "-c", "pass"}, redacted: []string{"process.argv"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			service, store := newTestService(t, config.CollectorDisabled, func(cfg *config.Config) {
				cfg.Detection.ExtendedProcessRules = true
				cfg.Detection.WebServices = []string{"example-web.service"}
				cfg.Collector.Audit.OnlyDetectionOrigins = true
				cfg.Collector.Tetragon.OnlyDetectionOrigins = true
			})
			defer store.Close()
			state, _, _ := managedPolicyFixture(t)
			ctx := context.Background()
			if err := store.SaveManagedState(ctx, state); err != nil {
				t.Fatal(err)
			}
			event := model.Event{ID: "scenario-event", Type: "process.exec", Source: test.source, BootID: "scenario-boot", EventTime: time.Now().UTC(),
				MissingFields: test.missing, RedactedFields: test.redacted,
				Process: model.Process{PID: 20001, PPID: 1, Exe: test.exe, Argv: test.argv, CWD: "/srv/application", UID: 1000, EUID: 1000, OriginService: test.origin},
			}
			for attempt := 0; attempt < 2; attempt++ {
				if err := service.processEvent(ctx, &event); err != nil {
					t.Fatal(err)
				}
			}
			findings, err := store.ListFindings(ctx, storage.FindingFilter{Limit: 20})
			if err != nil {
				t.Fatal(err)
			}
			if test.rule == "" {
				if len(findings) != 0 {
					t.Fatalf("legitimate/unsupported scenario produced findings: %+v", findings)
				}
				return
			}
			if len(findings) != 1 {
				t.Fatalf("retry must leave exactly one finding, got %d", len(findings))
			}
			finding := findings[0]
			if finding.RuleID != test.rule || finding.RiskScore != test.score || !finding.DetectionOnly || finding.ResponseDecision != "detection_only" {
				t.Fatalf("wrong rule/score or unsafe response: %+v", finding)
			}
			if len(finding.RiskFactors) < 2 || len(finding.RiskFactors) > 8 || len(finding.EvidenceEventIDs) != 1 || finding.EvidenceEventIDs[0] != event.ID {
				t.Fatalf("invalid bounded evidence: %+v", finding)
			}
			batch, err := store.DeliveryBatch(ctx, 64)
			if err != nil || len(batch.Records) != 1 {
				t.Fatalf("expected one atomic outbox record: %+v %v", batch, err)
			}
			var bundle managed.EventBundle
			if err := json.Unmarshal(batch.Records[0].Payload, &bundle); err != nil || len(bundle.Findings) != 1 {
				t.Fatalf("invalid delivered bundle: %+v %v", bundle, err)
			}
			if bundle.Findings[0].RiskScore != finding.RiskScore || !bundle.Findings[0].DetectionOnly || len(bundle.Findings[0].RiskFactors) != len(finding.RiskFactors) {
				t.Fatal("delivery lost detection metadata")
			}
		})
	}
}

func TestExtendedDetectionCannotBecomeAnEnforcementTarget(t *testing.T) {
	service, store := newTestService(t, config.CollectorDisabled, func(cfg *config.Config) {
		cfg.Response.AllowTerminate = true
	})
	_, policy, _ := managedPolicyFixture(t)
	policy.Response = managed.ResponsePolicy{Mode: "enforce", Action: "terminate", RiskThreshold: 1, MinConfidence: .01, RequiredCapabilities: []string{"observation.process_exec"}}
	findings := []model.Finding{{ID: "detector-only", Severity: "critical", Confidence: 1, RiskScore: 100,
		RiskFactors: []model.RiskFactor{{ID: "web_origin", Score: 25}}, DetectionOnly: true}}
	service.applyResponseDecisions(findings, &policy)
	if findings[0].RiskScore != 100 || findings[0].ResponseDecision != "detection_only" || findings[0].PolicyRevision != policy.Revision {
		t.Fatalf("enforcement bypassed detection-only marker or changed additive score: %+v", findings)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	// The actuator must independently honor the marker even if a caller passes
	// a pending action. A closed store also proves it never tries to claim it.
	findings[0].ResponseDecision = "terminate_pending"
	if err := service.executeResponses(context.Background(), model.Event{Source: "tetragon"}, findings, &policy); err != nil {
		t.Fatalf("detector-only finding reached actuator storage: %v", err)
	}
	if findings[0].ResponseDecision != "terminate_pending" {
		t.Fatal("actuator processed a detector-only finding")
	}
}

func TestExtendedManagedPolicyRequiresCompatibleCollectionScope(t *testing.T) {
	service, store := newTestService(t, config.CollectorDisabled, func(cfg *config.Config) {
		cfg.Collector.Tetragon.IncludeExecutables = []string{"sh", "bash"}
	})
	defer store.Close()
	state, policy, key := managedPolicyFixture(t)
	policy.Detection.Shells = []string{"sh", "bash"}
	ctx := context.Background()
	if err := service.applyManagedPolicy(ctx, signRuntimePolicy(t, policy, key), state, time.Now(), false); err != nil {
		t.Fatal(err)
	}
	previous := service.detectionState.Load()
	policy.Revision++
	policy.Detection.ExtendedProcessRules = true
	err := service.applyManagedPolicy(ctx, signRuntimePolicy(t, policy, key), state, time.Now(), false)
	if err == nil || !strings.Contains(err.Error(), "executable filters") || service.detectionState.Load() != previous {
		t.Fatalf("incomplete collector coverage replaced approved detector: %v", err)
	}
}

func TestExtendedSummaryReportsTheEffectivePolicyProfile(t *testing.T) {
	service, store := newTestService(t, config.CollectorDisabled, func(cfg *config.Config) {
		cfg.Detection.ExtendedProcessRules = true
		cfg.Response.AllowTerminate = true
	})
	defer store.Close()
	ctx := context.Background()
	summary, err := service.Summary(ctx)
	if err != nil || !summary.ExtendedProcessRules || summary.ResponseMode != "observe" {
		t.Fatalf("local profile: %+v %v", summary, err)
	}
	state, policy, key := managedPolicyFixture(t)
	if err := service.applyManagedPolicy(ctx, signRuntimePolicy(t, policy, key), state, time.Now(), false); err != nil {
		t.Fatal(err)
	}
	summary, err = service.Summary(ctx)
	if err != nil || summary.ExtendedProcessRules {
		t.Fatalf("local flag overrode approved central profile: %+v %v", summary, err)
	}
	policy.Revision++
	policy.Detection.ExtendedProcessRules = true
	if err := service.applyManagedPolicy(ctx, signRuntimePolicy(t, policy, key), state, time.Now(), false); err != nil {
		t.Fatal(err)
	}
	summary, err = service.Summary(ctx)
	if err != nil || !summary.ExtendedProcessRules || summary.ResponseMode != "observe" || summary.ResponseAction != "none" {
		t.Fatalf("managed detector-only profile: %+v %v", summary, err)
	}
	policy.Response.Mode, policy.Response.Action = "enforce", "terminate"
	active := service.detectionState.Load()
	service.detectionState.Store(&detectionState{engine: active.engine, enabled: true, policy: &policy})
	summary, err = service.Summary(ctx)
	if err != nil || summary.ResponseMode != "observe" || summary.ResponseAction != "none" {
		t.Fatalf("configured enforce misreported detector-only behavior: %+v %v", summary, err)
	}
}
