package storage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"xe-antishell/internal/model"
)

func TestOpenConfiguresDurableSQLite(t *testing.T) {
	store, path := openTestStore(t)

	var journalMode string
	if err := store.db.QueryRow(`PRAGMA journal_mode`).Scan(&journalMode); err != nil {
		t.Fatalf("read journal mode: %v", err)
	}
	if journalMode != "wal" {
		t.Fatalf("journal mode = %q, want wal", journalMode)
	}
	var synchronous int
	if err := store.db.QueryRow(`PRAGMA synchronous`).Scan(&synchronous); err != nil {
		t.Fatalf("read synchronous mode: %v", err)
	}
	if synchronous != 2 {
		t.Fatalf("synchronous = %d, want FULL (2)", synchronous)
	}
	var foreignKeys int
	if err := store.db.QueryRow(`PRAGMA foreign_keys`).Scan(&foreignKeys); err != nil {
		t.Fatalf("read foreign_keys: %v", err)
	}
	if foreignKeys != 1 {
		t.Fatalf("foreign_keys = %d, want 1", foreignKeys)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat database: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("database permissions = %o, want 600", got)
	}
}

func TestEventRoundTripFilteringAndConflict(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	first := testEvent("event-1", 1, time.Unix(100, 0).UTC())
	second := testEvent("event-2", 2, time.Unix(200, 0).UTC())
	second.Type = "process.exit"

	if err := store.SaveEvent(ctx, first); err != nil {
		t.Fatalf("save first event: %v", err)
	}
	if err := store.SaveEvent(ctx, second); err != nil {
		t.Fatalf("save second event: %v", err)
	}
	if err := store.SaveEvent(ctx, first); err != nil {
		t.Fatalf("idempotent save: %v", err)
	}

	got, err := store.GetEvent(ctx, first.ID)
	if err != nil {
		t.Fatalf("get event: %v", err)
	}
	if !reflect.DeepEqual(got, first) {
		t.Fatalf("event mismatch\n got: %#v\nwant: %#v", got, first)
	}

	listed, err := store.ListEvents(ctx, EventFilter{Type: "process.exec", Limit: 10})
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	if len(listed) != 1 || listed[0].ID != first.ID {
		t.Fatalf("filtered events = %#v", listed)
	}

	conflicting := first
	conflicting.Type = "file.open"
	if err := store.SaveEvent(ctx, conflicting); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting immutable event error = %v, want ErrConflict", err)
	}
	if _, err := store.GetEvent(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing event error = %v, want ErrNotFound", err)
	}
}

func TestStableSourceEventRetryIsDeduplicated(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	event := testEvent("stable-event", 10, time.Unix(100, 0).UTC())
	event.SourceEventID = "collector-42"
	inserted, err := store.SaveEventResult(ctx, event)
	if err != nil || !inserted {
		t.Fatalf("first SaveEventResult() = (%v, %v), want inserted", inserted, err)
	}
	retry := event
	retry.Sequence = 11
	retry.IngestTime = retry.IngestTime.Add(time.Minute)
	retry.Process.FirstSeen = retry.Process.FirstSeen.Add(time.Minute)
	retry.Process.LastSeen = retry.Process.LastSeen.Add(time.Minute)
	inserted, err = store.SaveEventResult(ctx, retry)
	if err != nil || inserted {
		t.Fatalf("retry SaveEventResult() = (%v, %v), want duplicate", inserted, err)
	}
	events, err := store.ListEvents(ctx, EventFilter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("retry created %d durable events", len(events))
	}
}

func TestProcessLookupHandlesPIDReuseAndChildren(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	bootID := "boot-a"
	parent := testProcess("proc-parent", 100, time.Unix(100, 0).UTC())
	child := testProcess("proc-child", 101, time.Unix(110, 0).UTC())
	child.ParentKey = parent.Key
	child.PPID = parent.PID

	if err := store.SaveProcess(ctx, bootID, parent); err != nil {
		t.Fatalf("save parent: %v", err)
	}
	if err := store.SaveProcess(ctx, bootID, child); err != nil {
		t.Fatalf("save child: %v", err)
	}
	children, err := store.ListChildProcesses(ctx, parent.Key, 10)
	if err != nil {
		t.Fatalf("list children: %v", err)
	}
	if len(children) != 1 || children[0].Key != child.Key {
		t.Fatalf("children = %#v", children)
	}

	reused := testProcess("proc-reused", parent.PID, time.Unix(300, 0).UTC())
	if err := store.SaveProcess(ctx, bootID, reused); err != nil {
		t.Fatalf("save reused PID: %v", err)
	}
	latest, err := store.FindLatestProcessByPID(ctx, bootID, parent.PID)
	if err != nil {
		t.Fatalf("find latest PID: %v", err)
	}
	if latest.Key != reused.Key {
		t.Fatalf("latest process = %q, want %q", latest.Key, reused.Key)
	}

	reused.LastSeen = reused.LastSeen.Add(time.Minute)
	if err := store.SaveProcess(ctx, bootID, reused); err != nil {
		t.Fatalf("update process: %v", err)
	}
	got, err := store.GetProcess(ctx, reused.Key)
	if err != nil {
		t.Fatalf("get process: %v", err)
	}
	if !got.LastSeen.Equal(reused.LastSeen) {
		t.Fatalf("updated last seen = %v, want %v", got.LastSeen, reused.LastSeen)
	}
	if err := store.SaveProcess(ctx, "boot-b", reused); !errors.Is(err, ErrConflict) {
		t.Fatalf("cross-boot process key error = %v, want ErrConflict", err)
	}
}

func TestProcessStorageAllowsSamePIDAndAuditTimestampAcrossExecs(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	bootID := "boot-a"
	started := time.Unix(300, 123_000_000).UTC()

	first := testProcess("proc-exec-1", 444, started)
	first.ExecID = "audit:100"
	second := testProcess("proc-exec-2", 444, started)
	second.ExecID = "audit:101"
	second.FirstSeen = second.FirstSeen.Add(time.Nanosecond)
	second.LastSeen = second.LastSeen.Add(time.Nanosecond)

	if err := store.SaveProcess(ctx, bootID, first); err != nil {
		t.Fatalf("save first exec: %v", err)
	}
	if err := store.SaveProcess(ctx, bootID, second); err != nil {
		t.Fatalf("save second exec with same PID/time: %v", err)
	}
	latest, err := store.FindLatestProcessByPID(ctx, bootID, first.PID)
	if err != nil {
		t.Fatalf("find latest equal-time exec: %v", err)
	}
	if latest.Key != second.Key {
		t.Fatalf("latest equal-time exec = %q, want %q", latest.Key, second.Key)
	}
	conflictingIdentity := first
	conflictingIdentity.Key = "proc-exec-conflict"
	if err := store.SaveProcess(ctx, bootID, conflictingIdentity); err == nil {
		t.Fatal("same collector execution identity was stored under two process keys")
	}
}

func TestFindingEvidenceIsAtomicAndRetained(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	event := testEvent("evidence-1", 1, time.Unix(100, 0).UTC())
	if err := store.SaveEvent(ctx, event); err != nil {
		t.Fatalf("save evidence event: %v", err)
	}
	finding := model.Finding{
		ID:               "finding-1",
		RuleID:           "web-shell",
		RuleVersion:      "1",
		CreatedAt:        time.Unix(200, 0).UTC(),
		Severity:         "high",
		Confidence:       0.9,
		State:            "open",
		Summary:          "web process launched a shell",
		ProcessKey:       event.Process.Key,
		EvidenceEventIDs: []string{event.ID},
		Source:           "local",
	}
	if err := store.SaveFinding(ctx, finding); err != nil {
		t.Fatalf("save finding: %v", err)
	}
	got, err := store.GetFinding(ctx, finding.ID)
	if err != nil {
		t.Fatalf("get finding: %v", err)
	}
	if !reflect.DeepEqual(got, finding) {
		t.Fatalf("finding mismatch\n got: %#v\nwant: %#v", got, finding)
	}
	listed, err := store.ListFindings(ctx, FindingFilter{State: "open", Limit: 10})
	if err != nil {
		t.Fatalf("list findings: %v", err)
	}
	if len(listed) != 1 || listed[0].ID != finding.ID {
		t.Fatalf("listed findings = %#v", listed)
	}

	missingEvidence := finding
	missingEvidence.ID = "finding-invalid"
	missingEvidence.EvidenceEventIDs = []string{"does-not-exist"}
	if err := store.SaveFinding(ctx, missingEvidence); err == nil {
		t.Fatal("save finding with missing evidence succeeded")
	}
	if _, err := store.GetFinding(ctx, missingEvidence.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rolled-back finding error = %v, want ErrNotFound", err)
	}

	deleted, err := store.DeleteEventsBefore(ctx, time.Unix(500, 0).UTC(), 100)
	if err != nil {
		t.Fatalf("delete expired events: %v", err)
	}
	if deleted != 0 {
		t.Fatalf("deleted evidence events = %d, want 0", deleted)
	}
}

func TestLatestCapabilityReport(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	older := testCapabilityReport(time.Unix(100, 0).UTC(), "5.14.0")
	newer := testCapabilityReport(time.Unix(200, 0).UTC(), "6.12.0")
	if err := store.SaveCapabilityReport(ctx, newer); err != nil {
		t.Fatalf("save newer report: %v", err)
	}
	if err := store.SaveCapabilityReport(ctx, older); err != nil {
		t.Fatalf("save older report: %v", err)
	}
	got, err := store.LatestCapabilityReport(ctx)
	if err != nil {
		t.Fatalf("latest report: %v", err)
	}
	if !reflect.DeepEqual(got, newer) {
		t.Fatalf("latest report = %#v, want %#v", got, newer)
	}
}

func TestOpenRejectsNewerSchema(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "sentinel.db")
	store, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if _, err := store.db.Exec(`
INSERT INTO schema_migrations(version, name, checksum, applied_at_ns)
VALUES (99, 'future.sql', 'future', 1)`); err != nil {
		t.Fatalf("insert future migration: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}
	if _, err := Open(ctx, path); err == nil {
		t.Fatal("opening newer schema succeeded")
	}
}

func TestOpenMigratesVersionOneProcessIdentityIndex(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "sentinel.db")
	store, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if _, err := store.db.Exec(`
DROP INDEX processes_execution_identity_idx;
CREATE UNIQUE INDEX processes_identity_idx
    ON processes(boot_id, pid, start_time_ns)
    WHERE boot_id <> '' AND start_time_ns > 0;
DELETE FROM schema_migrations WHERE version = 2;`); err != nil {
		t.Fatalf("restore version-one process index: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close version-one store: %v", err)
	}

	store, err = Open(ctx, path)
	if err != nil {
		t.Fatalf("migrate version-one store: %v", err)
	}
	defer store.Close()
	var count int
	if err := store.db.QueryRow(`
SELECT count(*) FROM sqlite_master
WHERE type = 'index' AND name = 'processes_execution_identity_idx'`).Scan(&count); err != nil {
		t.Fatalf("inspect migrated index: %v", err)
	}
	if count != 1 {
		t.Fatalf("migrated execution identity index count = %d, want 1", count)
	}
}

func openTestStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sentinel.db")
	store, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("close test store: %v", err)
		}
	})
	return store, path
}

func testEvent(id string, sequence uint64, eventTime time.Time) model.Event {
	return model.Event{
		SchemaVersion: model.SchemaVersion,
		ID:            id,
		HostID:        "host-1",
		BootID:        "boot-a",
		StreamID:      "exec",
		Sequence:      sequence,
		EventTime:     eventTime,
		IngestTime:    eventTime.Add(time.Second),
		Type:          "process.exec",
		Source:        "replay",
		Completeness:  model.CompletenessComplete,
		Process:       testProcess("process-"+id, 123, eventTime),
	}
}

func testProcess(key string, pid int, started time.Time) model.Process {
	return model.Process{
		Key:               key,
		PID:               pid,
		PPID:              1,
		StartTime:         started,
		Exe:               "/usr/bin/bash",
		Argv:              []string{"bash", "-c", "true"},
		UID:               1000,
		EUID:              1000,
		GID:               1000,
		EGID:              1000,
		LineageConfidence: model.LineageVerified,
		Complete:          true,
		FirstSeen:         started,
		LastSeen:          started.Add(time.Second),
	}
}

func testCapabilityReport(probedAt time.Time, kernel string) model.CapabilityReport {
	return model.CapabilityReport{
		ProbeVersion: "1",
		ProbedAt:     probedAt,
		Platform: model.Platform{
			Distribution:  "rocky",
			VersionID:     "9",
			KernelRelease: kernel,
			Architecture:  "x86_64",
			BootID:        "boot-a",
		},
		Capabilities: map[string]model.Capability{
			"process_exec": {
				Name:     "process_exec",
				State:    model.CapabilitySupported,
				Provider: "tetragon",
			},
		},
	}
}
