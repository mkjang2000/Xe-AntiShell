package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"xe-antishell/internal/agent"
)

func TestOfflineCompareReflectsChangesWithoutDaemon(t *testing.T) {
	base := "../../configs/sentineld.yaml"
	extended := "../../configs/examples/agent-webshell-detection.yaml"
	sample := "../../testdata/events/web-shell.jsonl"
	disabled := filepath.Join(t.TempDir(), "disabled.yaml")
	if err := os.WriteFile(disabled, []byte("version: 1\ndetection:\n  enabled: false\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		current, candidate      string
		added, removed, changed int
	}{
		{base, base, 0, 0, 0}, {base, extended, 0, 0, 1}, {disabled, base, 1, 0, 0}, {base, disabled, 0, 1, 0},
	} {
		var out, stderr bytes.Buffer
		err := run([]string{"--json", "rules", "compare", "--current", tc.current, "--candidate", tc.candidate, "--events", sample}, &out, &stderr)
		if err != nil {
			t.Fatal(err)
		}
		var report agent.RuleComparison
		if err := json.Unmarshal(out.Bytes(), &report); err != nil {
			t.Fatal(err)
		}
		if report.Events != 2 || len(report.Rules) != 16 || strings.Contains(out.String(), "/bin/bash") {
			t.Fatalf("unexpected report: %s", out.String())
		}
		for _, r := range report.Rules {
			if r.ID == "web-descendant-shell" && (r.Added != tc.added || r.Removed != tc.removed || r.Changed != tc.changed || !r.HasInputType) {
				t.Fatalf("unexpected difference: %+v", r)
			}
			if r.ID == "privilege-root-restored" && r.HasInputType {
				t.Fatal("claimed absent credential input")
			}
		}
	}
}

func TestOfflineCompareRejectsMixedBootAndIncompleteSamples(t *testing.T) {
	data, err := os.ReadFile("../../testdata/events/web-shell.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	for _, sample := range []string{"", "{bad json}", `{"event_type":"process.exec"}`, strings.Replace(string(data), `"event_type":`, `"boot_id":"other","event_type":`, 1)} {
		path := filepath.Join(t.TempDir(), "sample.jsonl")
		if err := os.WriteFile(path, []byte(sample), 0600); err != nil {
			t.Fatal(err)
		}
		var out, stderr bytes.Buffer
		if err := run([]string{"rules", "compare", "--current", "../../configs/sentineld.yaml", "--candidate", "../../configs/sentineld.yaml", "--events", path}, &out, &stderr); err == nil || out.Len() != 0 {
			t.Fatalf("reported success for invalid sample: %v %s", err, out.String())
		}
	}
}

func TestOfflineCompareServiceObservationExample(t *testing.T) {
	var out, stderr bytes.Buffer
	err := run([]string{"--json", "rules", "compare", "--current", "../../configs/sentineld.yaml",
		"--candidate", "../../configs/examples/agent-service-observations.yaml", "--events", "../../testdata/events/service-observations.jsonl"}, &out, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	var report agent.RuleComparison
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Events != 6 {
		t.Fatalf("unexpected event count %d", report.Events)
	}
	hits := 0
	for _, r := range report.Rules {
		if r.ID == "service-protected-file-write" || r.ID == "service-unexpected-tcp-destination" {
			if !r.HasInputType || r.Current != 0 || r.Candidate != 1 || r.Added != 1 || len(r.AffectedServices) != 1 || r.AffectedServices[0] != "example-web.service" {
				t.Fatalf("unexpected service observation comparison %+v", r)
			}
			hits++
		} else if r.Current+r.Candidate != 0 {
			t.Fatalf("unexpected finding for %s", r.ID)
		}
	}
	if hits != 2 {
		t.Fatalf("missing fixture rules: %d", hits)
	}
}
