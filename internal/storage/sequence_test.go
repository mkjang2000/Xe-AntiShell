package storage

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"xe-antishell/internal/model"
)

func TestLastSequenceSurvivesReopen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "sequence.db")
	store, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	event := model.Event{
		SchemaVersion: model.SchemaVersion,
		ID:            "event-sequence",
		BootID:        "boot-1",
		StreamID:      "process",
		Sequence:      41,
		EventTime:     now,
		IngestTime:    now,
		Type:          "process.exec",
		Source:        "test",
		Completeness:  model.CompletenessComplete,
	}
	if err := store.SaveEvent(ctx, event); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	sequence, err := store.LastSequence(ctx, "boot-1", "process")
	if err != nil {
		t.Fatal(err)
	}
	if sequence != 41 {
		t.Fatalf("LastSequence() = %d, want 41", sequence)
	}
	if _, err := store.DeleteEventsBefore(ctx, now.Add(time.Second), 100); err != nil {
		t.Fatal(err)
	}
	sequence, err = store.LastSequence(ctx, "boot-1", "process")
	if err != nil {
		t.Fatal(err)
	}
	if sequence != 41 {
		t.Fatalf("LastSequence() after retention = %d, want 41", sequence)
	}
}

func TestLastSequenceSeeksLegacyStreamWithoutWatermark(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	plan := storageQueryPlan(t, store.db, lastStreamEventSequence, "boot-a", "process")
	if !strings.Contains(plan, "USING COVERING INDEX events_stream_sequence_idx (boot_id=? AND stream_id=? AND sequence>?)") {
		t.Fatalf("unindexed startup query: %s", plan)
	}
	at := time.Unix(500, 0).UTC()
	for _, tc := range []struct {
		id, boot, stream string
		seq              uint64
	}{
		{"zero", "boot-a", "process", 0}, {"empty", "boot-a", "", 800},
		{"old", "boot-a", "process", 9}, {"other-boot", "boot-b", "process", 654},
		{"other-stream", "boot-a", "audit", 900}, {"new", "boot-a", "process", 81},
		{"only-zero", "boot-c", "process", 0},
	} {
		e := testEvent(tc.id, tc.seq, at)
		e.BootID, e.StreamID = tc.boot, tc.stream
		if err := store.SaveEvent(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.db.Exec("DELETE FROM metadata WHERE key=?", sequenceMetadataKey("boot-a", "process")); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		boot, stream string
		want         uint64
	}{
		{"boot-a", "process", 81}, {"boot-c", "process", 0}, {"missing", "process", 0}, {"boot-a", "audit", 900},
	} {
		got, err := store.LastSequence(ctx, tc.boot, tc.stream)
		if err != nil || got != tc.want {
			t.Fatalf("LastSequence(%s,%s) = %d, want %d: %v", tc.boot, tc.stream, got, tc.want, err)
		}
	}
}
