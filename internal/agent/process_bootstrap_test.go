package agent

import (
	"context"
	"errors"
	"testing"
	"time"

	"xe-antishell/internal/config"
	"xe-antishell/internal/model"
	"xe-antishell/internal/storage"
)

func TestSuccessfulLiveSnapshotDoesNotRestoreStaleDurableParent(t *testing.T) {
	cfg, store, prober := newTestDependencies(t, config.CollectorDisabled, nil)
	parent := durableWebParent()
	if err := store.SaveProcess(context.Background(), "boot-test", parent); err != nil {
		t.Fatal(err)
	}
	service, err := NewWithProcessSource(cfg, store, prober, staticProcessSource{})
	if err != nil {
		t.Fatal(err)
	}
	startService(t, service)
	if err := service.Submit(context.Background(), childShell(parent.PID)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		events, _ := store.ListEvents(context.Background(), storage.EventFilter{Limit: 10})
		return len(events) == 1
	})
	findings, err := store.ListFindings(context.Background(), storage.FindingFilter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("stale durable parent produced findings: %#v", findings)
	}
	shutdownService(t, service)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestFailedLiveSnapshotFallsBackToDurableLineage(t *testing.T) {
	cfg, store, prober := newTestDependencies(t, config.CollectorDisabled, nil)
	parent := durableWebParent()
	if err := store.SaveProcess(context.Background(), "boot-test", parent); err != nil {
		t.Fatal(err)
	}
	service, err := NewWithProcessSource(cfg, store, prober, staticProcessSource{snapshotErr: errors.New("proc unavailable")})
	if err != nil {
		t.Fatal(err)
	}
	startService(t, service)
	status, _ := service.Status(context.Background())
	if status.Health != model.HealthDegraded || status.LastError == "" {
		t.Fatalf("snapshot failure was not disclosed: %#v", status)
	}
	if err := service.Submit(context.Background(), childShell(parent.PID)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		findings, _ := store.ListFindings(context.Background(), storage.FindingFilter{Limit: 10})
		return len(findings) == 1
	})
	shutdownService(t, service)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}

func durableWebParent() model.Process {
	observed := time.Now().UTC().Add(-time.Hour)
	return model.Process{
		Key: "stale-web-parent", PID: 910, PPID: 1,
		StartTime: observed, Exe: "/usr/sbin/php-fpm",
		UID: 991, EUID: 991, GID: 991, EGID: 991,
		FirstSeen: observed, LastSeen: observed,
	}
}

func childShell(ppid int) model.Event {
	return model.Event{
		Type: "process.exec", Source: "test", EventTime: time.Now().UTC(),
		Process: model.Process{PID: 911, PPID: ppid, Exe: "/bin/bash", UID: 991, EUID: 991},
	}
}
