package agent

import (
	"context"
	"testing"
	"time"

	"xe-antishell/internal/config"
	"xe-antishell/internal/model"
	"xe-antishell/internal/storage"
)

func TestTetragonKeepsCandidateAndDurableParentContext(t *testing.T) {
	cfg, store, prober := newTestDependencies(t, config.CollectorDisabled, func(cfg *config.Config) {
		cfg.Collector.Tetragon.IncludeExecutables = []string{"bash"}
		cfg.Collector.Tetragon.OnlyDetectionOrigins = true
		cfg.Detection.WebServices = []string{"orders.service"}
	})
	defer store.Close()
	now := time.Now().UTC()
	service, err := NewWithProcessSource(cfg, store, prober, staticProcessSource{processes: []model.Process{{
		Key: "bootstrap-key", PID: 100, PPID: 1, Exe: "/usr/bin/python3", OriginService: "orders.service", StartTime: now.Add(-time.Minute),
	}}})
	if err != nil {
		t.Fatal(err)
	}
	startService(t, service)
	defer shutdownService(t, service)
	ctx := context.Background()
	parent := model.Process{Key: "source-parent", ExecID: "parent-exec", PID: 100, PPID: 1, Exe: "/usr/bin/python3", StartTime: now.Add(-time.Minute), Argv: []string{"--token", "private-value"}}
	candidate := model.Event{ID: "candidate", Type: "process.exec", Source: "tetragon", EventTime: now, Ancestors: []model.Process{parent}, Process: model.Process{
		Key: "source-shell", ExecID: "shell-exec", PID: 101, PPID: 100, ParentKey: parent.Key,
		Exe: "/usr/bin/bash", UID: 1000, EUID: 1000, LineageConfidence: model.LineageVerified,
	}}
	if err := service.processEvent(ctx, &candidate); err != nil {
		t.Fatal(err)
	}
	if candidate.Process.OriginService != "orders.service" {
		t.Fatalf("bootstrap service context was lost: %#v", candidate.Process)
	}
	parentRow, err := store.GetProcess(ctx, parent.Key)
	if err != nil || len(parentRow.Argv) != 0 {
		t.Fatalf("durable parent context or privacy: %#v %v", parentRow, err)
	}
	for _, event := range []model.Event{
		{ID: "unrelated", Type: "process.exec", Source: "tetragon", EventTime: now, Process: model.Process{PID: 200, Exe: "/usr/bin/bash"}},
		{ID: "nonshell", Type: "process.exec", Source: "tetragon", EventTime: now, Process: model.Process{PID: 201, Exe: "/usr/bin/curl", OriginService: "orders.service"}},
	} {
		if err := service.processEvent(ctx, &event); err != nil {
			t.Fatal(err)
		}
	}
	exit := candidate
	exit.ID, exit.Type = "candidate-exit", "process.exit"
	exit.Sequence = 0
	exit.EventTime = now.Add(time.Second)
	if err := service.processEvent(ctx, &exit); err != nil {
		t.Fatal(err)
	}
	events, err := store.ListEvents(ctx, storage.EventFilter{Limit: 20})
	if err != nil || len(events) != 2 {
		t.Fatalf("only candidate exec/exit should be durable: %d %v", len(events), err)
	}
	findings, err := store.ListFindings(ctx, storage.FindingFilter{Limit: 20})
	if err != nil || len(findings) != 1 || findings[0].Severity != "high" {
		t.Fatalf("candidate finding: %#v %v", findings, err)
	}
}
