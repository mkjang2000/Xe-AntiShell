package agent

import (
	"context"
	"testing"
	"time"

	"xe-antishell/internal/config"
	"xe-antishell/internal/model"
	"xe-antishell/internal/storage"
)

func TestAuditOriginFilterDropsUnrelatedShellBeforeLineageAndStorage(t *testing.T) {
	cfg, store, prober := newTestDependencies(t, config.CollectorDisabled, func(cfg *config.Config) {
		cfg.Collector.Audit.OnlyDetectionOrigins = true
	})
	service, err := NewWithProcessSource(cfg, store, prober, staticProcessSource{origin: "rustdesk.service"})
	if err != nil {
		t.Fatal(err)
	}
	startService(t, service)
	if err := service.Submit(context.Background(), auditShellEvent(1001, 1000)); err != nil {
		t.Fatal(err)
	}
	shutdownService(t, service)

	events, err := store.ListEvents(context.Background(), storage.EventFilter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Fatalf("unrelated audit shell was stored: %#v", events)
	}
	if _, exists := service.lineage.CurrentByPID(1001); exists {
		t.Fatal("filtered audit shell remained in lineage")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestAuditOriginFilterStoresAllowedWebCandidateWithoutFinding(t *testing.T) {
	cfg, store, prober := newTestDependencies(t, config.CollectorDisabled, func(cfg *config.Config) {
		cfg.Collector.Audit.OnlyDetectionOrigins = true
		cfg.Detection.WebServices = append(cfg.Detection.WebServices, "payments.service")
		cfg.Detection.AllowedPairs = []string{"payments.service:sh"}
	})
	service, err := NewWithProcessSource(cfg, store, prober, staticProcessSource{origin: "payments.service"})
	if err != nil {
		t.Fatal(err)
	}
	startService(t, service)
	if err := service.Submit(context.Background(), auditShellEvent(1002, 1000)); err != nil {
		t.Fatal(err)
	}
	shutdownService(t, service)

	events, err := store.ListEvents(context.Background(), storage.EventFilter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Process.OriginService != "payments.service" {
		t.Fatalf("allowed web candidate was not retained: %#v", events)
	}
	findings, err := store.ListFindings(context.Background(), storage.FindingFilter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("allowed web candidate produced findings: %#v", findings)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestAuditOriginFilterDoesNotAffectOtherSources(t *testing.T) {
	cfg, store, prober := newTestDependencies(t, config.CollectorDisabled, func(cfg *config.Config) {
		cfg.Collector.Audit.OnlyDetectionOrigins = true
	})
	service, err := NewWithProcessSource(cfg, store, prober, staticProcessSource{origin: "rustdesk.service"})
	if err != nil {
		t.Fatal(err)
	}
	startService(t, service)
	event := auditShellEvent(1003, 1000)
	event.Source = "test"
	if err := service.Submit(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	shutdownService(t, service)

	events, err := store.ListEvents(context.Background(), storage.EventFilter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("non-audit event was filtered: %#v", events)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}

func auditShellEvent(pid, ppid int) model.Event {
	return model.Event{
		Type: "process.exec", Source: "audit", EventTime: time.Now().UTC(),
		Process: model.Process{PID: pid, PPID: ppid, Exe: "/bin/sh", UID: 1000, EUID: 1000},
	}
}
