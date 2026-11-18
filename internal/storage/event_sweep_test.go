package storage

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

func TestEventSweepUsesBoundedIndexSeeks(t *testing.T) {
	s, _ := openTestStore(t)
	for _, query := range []string{lastEventInFullPage, deleteEventPage} {
		plan := storageQueryPlan(t, s.db, query, 123, 4, 100)
		for _, seek := range []string{"events_event_time_idx (event_time_ns=? AND rowid>?)", "events_event_time_idx (event_time_ns<?)"} {
			if !strings.Contains(plan, seek) || strings.Contains(plan, "TEMP B-TREE") {
				t.Fatalf("event page lacks bounded seek %q:\n%s", seek, plan)
			}
		}
	}
	plan := storageQueryPlan(t, s.db, deleteEventPage, 123, 4, 100)
	for _, seek := range []string{"SEARCH e USING INTEGER PRIMARY KEY (rowid=?)", "finding_events_event_idx (event_id=?)", "(kind=? AND record_id=?)"} {
		if !strings.Contains(plan, seek) {
			t.Fatalf("event retention lacks reference/row seek %q:\n%s", seek, plan)
		}
	}
}

func TestEventSweepResumesPastProtectedPages(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "event-pages.db")
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { s.Close() }()
	at := time.Unix(100, 0).UTC()
	cutoff := at.Add(time.Hour)
	if err := s.SaveManagedState(ctx, ManagedState{AgentID: "agent", EnrollmentID: "enrollment", KeyPEM: "test"}); err != nil {
		t.Fatal(err)
	}
	var seq uint64
	save := func(id string, tm time.Time, pin string) {
		t.Helper()
		seq++
		e := testEvent(id, seq, tm)
		if pin == "delivery" {
			if err := s.PersistObservation(ctx, e, nil); err != nil {
				t.Fatal(err)
			}
			return
		}
		if err := s.SaveEvent(ctx, e); err != nil {
			t.Fatal(err)
		}
		if pin == "finding" {
			if err := s.SaveFinding(ctx, managedTestFinding(e)); err != nil {
				t.Fatal(err)
			}
		}
	}
	save("evidence", at, "finding")
	save("outbox", at, "delivery")
	save("expired", at, "")
	save("evidence2", at, "finding")
	save("older", at.Add(-time.Minute), "")
	save("fresh", cutoff, "")
	check := func(id string, exists bool) {
		t.Helper()
		_, err := s.GetEvent(ctx, id)
		if (exists && err != nil) || (!exists && !errors.Is(err, ErrNotFound)) {
			t.Fatalf("event %q want exists=%t: %v", id, exists, err)
		}
	}
	page := func(wantMore bool) {
		t.Helper()
		more, err := s.SweepEventsBefore(ctx, cutoff, 2)
		if err != nil || more != wantMore {
			t.Fatalf("continuation=%t, want %t: %v", more, wantMore, err)
		}
	}
	page(true) // Equal timestamps, first page entirely pinned.
	check("outbox", true)
	check("expired", true)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("CREATE TRIGGER fail_progress BEFORE UPDATE ON metadata WHEN NEW.key='retention:event_time_sweep' BEGIN SELECT RAISE(ABORT,'test'); END"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SweepEventsBefore(ctx, cutoff, 2); err == nil {
		t.Fatal("injected cursor failure should roll back deletion")
	}
	check("expired", true)
	if _, err := s.db.Exec("DROP TRIGGER fail_progress"); err != nil {
		t.Fatal(err)
	}
	page(true)
	check("expired", false)
	check("evidence2", true)
	batch, err := s.DeliveryBatch(ctx, 2)
	if err != nil || len(batch.Records) != 1 {
		t.Fatalf("pending delivery: %+v %v", batch, err)
	}
	if err := s.Acknowledge(ctx, managed.Ack{SpoolID: batch.SpoolID, Acknowledged: batch.Records[0].Sequence}, batch); err != nil {
		t.Fatal(err)
	}
	save("late", at.Add(time.Minute), "")
	page(false)
	check("older", false)
	check("outbox", true)
	check("late", true)
	page(true)
	page(true)
	page(false)
	check("outbox", false)
	check("late", false)
	check("fresh", true)
	check("evidence", true)
	check("evidence2", true)
}

func TestEventSweepRespectsLongerRetentionDuringPass(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()
	at := time.Unix(100, 0).UTC()
	for index, id := range []string{"first", "same-time", "older"} {
		tm := at
		if id == "older" {
			tm = at.Add(-time.Second)
		}
		if err := s.SaveEvent(ctx, testEvent(id, uint64(index+1), tm)); err != nil {
			t.Fatal(err)
		}
	}
	if more, err := s.SweepEventsBefore(ctx, at.Add(time.Hour), 1); err != nil || !more {
		t.Fatalf("first page: more=%t, err=%v", more, err)
	}
	if _, err := s.SweepEventsBefore(ctx, at, 5); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetEvent(ctx, "same-time"); err != nil {
		t.Fatalf("event at new cutoff deleted: %v", err)
	}
	if _, err := s.GetEvent(ctx, "older"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired event still present: %v", err)
	}
}
