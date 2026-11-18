package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func TestCompareServiceExceptionUsesSameFixedEvaluationClock(t *testing.T) {
	current := "../../configs/examples/agent-service-observations.yaml"
	raw, err := os.ReadFile(current)
	if err != nil {
		t.Fatal(err)
	}
	candidate := filepath.Join(t.TempDir(), "candidate.yaml")
	raw = bytes.Replace(raw, []byte("  enabled: true"), []byte("  enabled: true\n  service_rule_controls:\n    - service: example-web.service\n      rule_id: service-protected-file-write\n      mode: suppress_until\n      reason: approved rollout\n      expires_at: 2030-01-01T00:00:00Z"), 1)
	if err := os.WriteFile(candidate, raw, 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		at      string
		removed int
	}{{"2029-12-31T23:59:59.999999999Z", 1}, {"2030-01-01T00:00:00Z", 0}} {
		var stdout, stderr bytes.Buffer
		err := run([]string{"--json", "rules", "compare", "--at", tc.at, "--current", current, "--candidate", candidate, "--events", "../../testdata/events/service-observations.jsonl"}, &stdout, &stderr)
		if err != nil {
			t.Fatal(err)
		}
		var got agent.RuleComparison
		if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if got.EvaluatedAt.Format(time.RFC3339Nano) != tc.at {
			t.Fatal("wrong comparison clock")
		}
		seen := false
		for _, r := range got.Rules {
			if r.ID == "service-protected-file-write" {
				seen = true
				if r.Removed != tc.removed || r.Current != 1 {
					t.Fatalf("wrong comparison at %s: %+v", tc.at, r)
				}
			}
		}
		if !seen {
			t.Fatal("file rule missing")
		}
	}
}
