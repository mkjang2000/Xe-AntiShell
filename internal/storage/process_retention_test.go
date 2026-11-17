package storage

import (
	"context"
	"errors"
	"testing"
	"time"

	"xe-antishell/internal/model"
)

func TestDeleteProcessesBeforePreservesDurableReferences(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	old := time.Unix(100, 0).UTC()
	cutoff := time.Unix(500, 0).UTC()

	orphan := testProcess("orphan", 101, old)
	eventProcess := testProcess("event-process", 102, old)
	findingProcess := testProcess("finding-process", 103, old)
	fresh := testProcess("fresh", 104, time.Unix(600, 0).UTC())
	for _, process := range []model.Process{orphan, eventProcess, findingProcess, fresh} {
		if err := store.SaveProcess(ctx, "boot-a", process); err != nil {
			t.Fatalf("save process %q: %v", process.Key, err)
		}
	}

	event := testEvent("retained", 1, time.Unix(600, 0).UTC())
	event.Process = eventProcess
	if err := store.SaveEvent(ctx, event); err != nil {
		t.Fatalf("save retained event: %v", err)
	}
	finding := model.Finding{
		ID: "retained-finding", RuleID: "test", RuleVersion: "1",
		CreatedAt: event.EventTime, Severity: "high", Confidence: 1,
		State: "open", ProcessKey: findingProcess.Key,
		EvidenceEventIDs: []string{event.ID}, Source: "local",
	}
	if err := store.SaveFinding(ctx, finding); err != nil {
		t.Fatalf("save retained finding: %v", err)
	}

	deleted, err := store.DeleteProcessesBefore(ctx, cutoff, 100)
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 1 {
		t.Fatalf("deleted processes = %d, want 1", deleted)
	}
	if _, err := store.GetProcess(ctx, orphan.Key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("orphan lookup error = %v, want ErrNotFound", err)
	}
	for _, key := range []string{eventProcess.Key, findingProcess.Key, fresh.Key} {
		if _, err := store.GetProcess(ctx, key); err != nil {
			t.Fatalf("retained process %q: %v", key, err)
		}
	}
}

func TestDeleteProcessesBeforeIsBounded(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	old := time.Unix(100, 0).UTC()
	for index, key := range []string{"old-a", "old-b"} {
		if err := store.SaveProcess(ctx, "boot-a", testProcess(key, 200+index, old.Add(time.Duration(index)*time.Second))); err != nil {
			t.Fatal(err)
		}
	}
	deleted, err := store.DeleteProcessesBefore(ctx, time.Unix(500, 0).UTC(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 1 {
		t.Fatalf("deleted processes = %d, want 1", deleted)
	}
}
