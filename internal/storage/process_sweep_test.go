package storage

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"xe-antishell/internal/model"
)

func TestProcessSweepIndexedBoundaries(t *testing.T) {
	store, _ := openTestStore(t)
	bounds := storageQueryPlan(t, store.db, processPageBounds, 10, 100, 3)
	if !strings.Contains(bounds, "SEARCH processes USING INTEGER PRIMARY KEY (rowid>? AND rowid<?)") || strings.Contains(bounds, "TEMP B-TREE") {
		t.Fatalf("unbounded process page: %s", bounds)
	}
	plan := storageQueryPlan(t, store.db, deleteProcessPage, 10, 50, 1000)
	for _, seek := range []string{"SEARCH p USING INTEGER PRIMARY KEY (rowid>? AND rowid<?)", "SEARCH e USING COVERING INDEX events_process_time_idx", "SEARCH f USING COVERING INDEX findings_process_idx"} {
		if !strings.Contains(plan, seek) {
			t.Fatalf("missing %q: %s", seek, plan)
		}
	}
}

func TestProcessSweepDurableCursorWithPinnedRowsAndContinuousInserts(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "process-pages.db")
	store, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	}()
	old := time.Unix(100, 0).UTC()
	cutoff := old.Add(time.Hour)
	save := func(key string, pid int, at time.Time) model.Process {
		t.Helper()
		p := testProcess(key, pid, at)
		if err := store.SaveProcess(ctx, "boot-a", p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	pinned := save("event-pinned", 101, old)
	referred := save("finding-pinned", 102, old)
	save("orphan", 103, old)
	save("fresh", 104, cutoff)
	save("orphan2", 105, old)
	e := testEvent("evidence", 1, cutoff)
	e.Process = pinned
	if err := store.SaveEvent(ctx, e); err != nil {
		t.Fatal(err)
	}
	f := managedTestFinding(e)
	f.ProcessKey = referred.Key
	if err := store.SaveFinding(ctx, f); err != nil {
		t.Fatal(err)
	}
	check := func(key string, want bool) {
		t.Helper()
		_, err := store.GetProcess(ctx, key)
		if (want && err != nil) || (!want && !errors.Is(err, ErrNotFound)) {
			t.Fatalf("process %q present=%t: %v", key, want, err)
		}
	}
	page := func(wantMore bool) {
		t.Helper()
		got, err := store.SweepProcessesBefore(ctx, cutoff, 2)
		if err != nil || got != wantMore {
			t.Fatalf("page continuation=%v, want %v: %v", got, wantMore, err)
		}
	}
	page(true) // No deletes in a completely protected page.
	check("orphan", true)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}

	// Fail the progress write after a successful orphan DELETE and verify both
	// effects rolled back. The next run retries the same range.
	if _, err := store.db.Exec("CREATE TRIGGER bad_save BEFORE UPDATE ON metadata WHEN NEW.key='retention:process_rowid_sweep' BEGIN SELECT RAISE(ABORT,'test'); END"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SweepProcessesBefore(ctx, cutoff, 2); err == nil {
		t.Fatal("page progress should fail")
	}
	check("orphan", true)
	if _, err := store.db.Exec("DROP TRIGGER bad_save"); err != nil {
		t.Fatal(err)
	}
	save("added-during-sweep", 106, old)
	page(true)
	check("orphan", false)
	check("fresh", true)
	page(false)
	check("orphan2", false)
	check("added-during-sweep", true)
	page(true)
	page(false)
	check("added-during-sweep", false)
	check("event-pinned", true)
	check("finding-pinned", true)
	// An empty table requires just one bounded pass with no cursor write.
	if _, err := store.db.Exec("DELETE FROM processes"); err != nil {
		t.Fatal(err)
	}
	page(false)
}

func TestProcessSweepYieldsOnCanceledContext(t *testing.T) {
	store, _ := openTestStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.SweepProcessesBefore(ctx, time.Now(), 100); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled sweep: %v", err)
	}
}
