package storage

import (
	"context"
	"path/filepath"
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
