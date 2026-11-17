package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"xe-antishell/internal/capability"
	"xe-antishell/internal/collector"
	"xe-antishell/internal/config"
	"xe-antishell/internal/model"
	"xe-antishell/internal/storage"
)

func TestCapabilityProberUsesConfiguredTetraCommand(t *testing.T) {
	for _, injected := range []bool{false, true} {
		name := "default"
		if injected {
			name = "injected"
		}
		t.Run(name, func(t *testing.T) {
			cfg, store, _ := newTestDependencies(t, config.CollectorAuto, func(cfg *config.Config) {
				cfg.Collector.Tetragon.Command = "/opt/xe-antishell/tetragon/v1.8.0/tetra"
			})
			defer store.Close()
			var supplied CapabilityProber
			wantCommand := cfg.Collector.Tetragon.Command
			if injected {
				custom := capability.NewProber()
				custom.ConfiguredTetraCommand = "/custom/tetra"
				wantCommand = custom.ConfiguredTetraCommand
				supplied = custom
			}
			s, err := NewWithProcessSource(cfg, store, supplied, staticProcessSource{})
			if err != nil {
				t.Fatal(err)
			}
			if injected && s.prober != supplied {
				t.Fatal("injected capability prober was replaced")
			}
			p := s.prober.(*capability.Prober)
			p.Root = t.TempDir()
			btfPath := filepath.Join(p.Root, "sys/kernel/btf/vmlinux")
			if err := os.MkdirAll(filepath.Dir(btfPath), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(btfPath, []byte("btf"), 0o600); err != nil {
				t.Fatal(err)
			}
			p.Uname = func() (string, string, error) { return "5.14.0-test", "x86_64", nil }
			wantPath := filepath.Join(p.Root, wantCommand[1:])
			p.LookPath = func(path string) (string, error) {
				if path == wantPath {
					return path, nil
				}
				return "", errors.New("not found")
			}
			report, err := s.RefreshCapabilities(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			value := report.Capabilities[capability.TetragonCapability]
			if value.State != model.CapabilityLimited || value.Details["configured_command"] != wantCommand || value.Details["tetra"] != wantPath || value.RuntimeState == "active" {
				t.Fatalf("capability probe did not use its configured client: %#v", value)
			}
		})
	}
}

type runtimeTestCollector struct {
	mu     sync.Mutex
	health collector.HealthSnapshot
}

func (c *runtimeTestCollector) Name() string { return "tetragon-json" }
func (c *runtimeTestCollector) Probe(context.Context) collector.ProbeResult {
	return collector.ProbeResult{Available: true, Usable: true}
}
func (c *runtimeTestCollector) Run(context.Context, collector.EventSink) error { return nil }
func (c *runtimeTestCollector) Health() collector.HealthSnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.health
}
func (c *runtimeTestCollector) Close() error { return nil }

func setTestCollector(s *Service, c collector.Collector) {
	s.collectorMu.Lock()
	s.collector = c
	s.collectorMu.Unlock()
}

func prepareRuntimeReport(s *Service) {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	for _, name := range []string{capability.AuditCapability, capability.TetragonCapability, capability.ProcessExecCapability, capability.ProcessLineageCapability, capability.EBPFCapability} {
		s.report.Capabilities[name] = model.Capability{Name: name, State: model.CapabilityLimited, Reason: "passive prerequisites only", Details: map[string]string{"probe": "unchanged"}}
	}
	for _, name := range []string{capability.IMACapability, capability.TPMCapability, capability.FileCapability} {
		s.report.Capabilities[name] = model.Capability{Name: name, State: model.CapabilitySupported, Reason: "fixture interface available"}
	}
}

func TestRuntimeCapabilitiesRequireSelectedSourceEvidence(t *testing.T) {
	s, store := newTestService(t, config.CollectorDisabled, nil)
	startService(t, s)
	defer store.Close()
	defer shutdownService(t, s)
	prepareRuntimeReport(s)
	selected := &runtimeTestCollector{health: collector.HealthSnapshot{Name: "tetragon-json", Running: true}}
	setTestCollector(s, selected)
	s.setRuntimeState(model.AgentModeActive, model.HealthHealthy, "tetragon-json", nil)
	assertRuntime := func(name, state string) model.Capability {
		t.Helper()
		report, err := s.Capabilities(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		value := report.Capabilities[name]
		if value.RuntimeState != state {
			t.Fatalf("%s runtime=%s, want %s (%s)", name, value.RuntimeState, state, value.RuntimeReason)
		}
		return value
	}
	assertRuntime(capability.TetragonCapability, "unverified")
	assertRuntime(capability.ProcessExecCapability, "unverified")
	status, _ := s.Status(context.Background())
	if status.Health != model.HealthStarting {
		t.Fatalf("command startup claimed healthy source before receipt: %s", status.Health)
	}
	event := model.Event{Type: "process.exec", Source: "replay", Process: model.Process{PID: 100, Exe: "/bin/sh"}}
	s.recordRuntimeEvent(event)
	event.Source = "audit"
	s.recordRuntimeEvent(event)
	assertRuntime(capability.TetragonCapability, "unverified")
	event.Source = "tetragon"
	s.recordRuntimeEvent(event)
	value := assertRuntime(capability.ProcessExecCapability, "active")
	if value.State != model.CapabilityLimited || value.VerifiedAt == nil {
		t.Fatalf("passive state changed or active evidence time missing: %#v", value)
	}
	assertRuntime(capability.AuditCapability, "inactive")
	assertRuntime(capability.ProcessLineageCapability, "unverified")
	event.Process.ParentKey = "parent"
	event.Process.LineageConfidence = model.LineageInferred
	s.recordRuntimeEvent(event)
	assertRuntime(capability.ProcessLineageCapability, "unverified")
	event.Process.LineageConfidence = model.LineageVerified
	s.recordRuntimeEvent(event)
	assertRuntime(capability.ProcessLineageCapability, "active")
	assertRuntime(capability.EBPFCapability, "active")
	status, _ = s.Status(context.Background())
	if status.Health != model.HealthHealthy || status.CollectorHealth == nil {
		t.Fatalf("live collector status = %#v", status)
	}
}

func TestAuditRuntimeEvidencePrecedesCandidateFilter(t *testing.T) {
	s, store := newTestService(t, config.CollectorAudit, func(cfg *config.Config) {
		cfg.Collector.Audit.OnlyDetectionOrigins = true
	})
	startService(t, s)
	defer store.Close()
	defer shutdownService(t, s)
	prepareRuntimeReport(s)
	event := model.Event{Type: "process.exec", Source: "audit", EventTime: time.Now().UTC(), Process: model.Process{PID: 101, PPID: 1, Exe: "/bin/sh", OriginService: "unregistered.service"}}
	if err := s.processEvent(context.Background(), &event); err != nil {
		t.Fatal(err)
	}
	stored, err := store.ListEvents(context.Background(), storage.EventFilter{Limit: 10})
	if err != nil || len(stored) != 0 {
		t.Fatalf("filtered event persisted: len=%d err=%v", len(stored), err)
	}
	report, _ := s.Capabilities(context.Background())
	if report.Capabilities[capability.ProcessExecCapability].RuntimeState != "active" {
		t.Fatalf("filtered stream evidence was lost: %#v", report.Capabilities)
	}
	if report.Capabilities[capability.ProcessExecCapability].State != model.CapabilityLimited {
		t.Fatal("audit source coverage limitations were removed")
	}
}

func TestRuntimeRefreshAndReturnedReportsAreIndependent(t *testing.T) {
	s, store := newTestService(t, config.CollectorAudit, nil)
	startService(t, s)
	defer store.Close()
	defer shutdownService(t, s)
	prepareRuntimeReport(s)
	s.recordRuntimeEvent(model.Event{Type: "process.exec", Source: "audit", Process: model.Process{PID: 102, Exe: "/bin/sh"}})
	report, _ := s.Capabilities(context.Background())
	value := report.Capabilities[capability.AuditCapability]
	value.Details["probe"] = "modified"
	*value.VerifiedAt = time.Time{}
	report.Capabilities[capability.AuditCapability] = model.Capability{Name: "modified"}
	report, _ = s.Capabilities(context.Background())
	if report.Capabilities[capability.AuditCapability].Details["probe"] != "unchanged" || report.Capabilities[capability.AuditCapability].RuntimeState != "active" || report.Capabilities[capability.AuditCapability].VerifiedAt.IsZero() {
		t.Fatalf("external report mutation affected runtime: %#v", report.Capabilities[capability.AuditCapability])
	}
	report, err := s.RefreshCapabilities(context.Background())
	if err != nil || report.Capabilities[capability.AuditCapability].RuntimeState != "active" {
		t.Fatalf("refresh removed runtime receipt evidence: report=%#v err=%v", report, err)
	}
	passive, err := store.LatestCapabilityReport(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if passive.Capabilities[capability.AuditCapability].RuntimeState != "" {
		t.Fatal("ephemeral runtime evidence persisted as a passive probe")
	}
}

func TestRuntimeCollectorFailureOverridesPriorSuccess(t *testing.T) {
	s, store := newTestService(t, config.CollectorDisabled, nil)
	startService(t, s)
	defer store.Close()
	defer shutdownService(t, s)
	prepareRuntimeReport(s)
	selected := &runtimeTestCollector{health: collector.HealthSnapshot{Name: "tetragon-json", Running: true}}
	setTestCollector(s, selected)
	s.setRuntimeState(model.AgentModeActive, model.HealthHealthy, "tetragon-json", nil)
	s.recordRuntimeEvent(model.Event{Type: "process.exec", Source: "tetragon", Process: model.Process{PID: 103, Exe: "/bin/sh"}})
	selected.mu.Lock()
	selected.health.ParseErrors = 2
	selected.health.EventsDropped = 3
	selected.health.LastError = "invalid source event"
	selected.mu.Unlock()
	status, _ := s.Status(context.Background())
	if status.Health != model.HealthError || status.CollectorHealth.ParseErrors != 2 || status.CollectorHealth.EventsSkipped != 3 || status.Dropped != 0 {
		t.Fatalf("collector error/counters absent or intentional skips counted as loss: %#v", status)
	}
	if status.CapabilityReport.Capabilities[capability.TetragonCapability].RuntimeState != "error" {
		t.Fatal("failed collector retained active capability")
	}
	s.setRuntimeState(model.AgentModeDegraded, model.HealthDegraded, "tetragon-json", errors.New("collector stream ended"))
	selected.mu.Lock()
	selected.health.Running = false
	selected.health.LastError = ""
	selected.mu.Unlock()
	report, _ := s.Capabilities(context.Background())
	if report.Capabilities[capability.TetragonCapability].RuntimeState != "error" {
		t.Fatal("ended stream retained active capability")
	}
}

func TestIntegrityPrerequisitesNeverClaimActiveVerification(t *testing.T) {
	s, store := newTestService(t, config.CollectorDisabled, nil)
	startService(t, s)
	defer store.Close()
	defer shutdownService(t, s)
	prepareRuntimeReport(s)
	report, _ := s.Capabilities(context.Background())
	for _, name := range []string{capability.IMACapability, capability.TPMCapability, capability.FileCapability} {
		value := report.Capabilities[name]
		if value.Implementation != "planned" || value.RuntimeState != "inactive" {
			t.Fatalf("%s claims an implemented verifier: %#v", name, value)
		}
	}
	if report.Capabilities[capability.IMACapability].State != model.CapabilitySupported {
		t.Fatal("passive IMA prerequisite state was lost")
	}
}
