package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigAllowsOnlyMissingDefault(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.yaml")
	if _, err := loadConfig(missing, true); err != nil {
		t.Fatalf("allowed missing default: %v", err)
	}
	if _, err := loadConfig(missing, false); err == nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("explicit missing config should fail, got %v", err)
	}
}

func TestRunRejectsExplicitMissingCustomConfig(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.yaml")
	if err := run([]string{"--config", missing}); err == nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected missing explicit config error, got %v", err)
	}
}

func TestRunRejectsConflictingReplayFlagsBeforeMutation(t *testing.T) {
	err := run([]string{"--collector", "audit", "--replay", "/tmp/events.jsonl"})
	if err == nil {
		t.Fatal("expected conflicting collector/replay error")
	}
}
