package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

func TestManagedImpactBindsFileBytesAndExactPolicies(t *testing.T) {
	at := time.Date(2026, 11, 18, 5, 0, 0, 0, time.UTC)
	p := managed.DefaultPolicy("agent-a", "enrollment-abcdefgh", 1, at)
	p.Detection.WebServices = []string{"example-web.service"}
	q := p
	q.Revision = 2
	empty := []managed.ServiceObservationPolicy{}
	q.Detection.ServiceObservations = &empty
	input := managed.PolicyImpactInput{TrialID: "trial-example", EvaluatedAt: at, Current: p, Candidate: q}
	b, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "input.json")
	if err = os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	host := "../../configs/examples/agent-service-observations.yaml"
	events := "../../testdata/events/service-observations.jsonl"
	var out, stderr bytes.Buffer
	if err := run([]string{"rules", "compare", "--managed-input", path, "--host-config", host, "--events", events}, &out, &stderr); err != nil {
		t.Fatal(err)
	}
	var r managed.PolicyImpactReport
	if err = json.Unmarshal(out.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if err = r.ValidateFor(input); err != nil {
		t.Fatal(err)
	}
	sample, _ := os.ReadFile(events)
	if r.SampleDigest != fmt.Sprintf("%x", sha256.Sum256(sample)) || strings.Contains(out.String(), "/srv/") {
		t.Fatal("raw sample or incorrect sample digest")
	}
	removed := 0
	for _, rule := range r.Rules {
		removed += rule.Removed
	}
	if removed != 2 {
		t.Fatalf("expected local file/tcp scopes disabled with signed empty override: %+v", r.Rules)
	}
	changed := input
	changed.Candidate.ID = "different"
	if r.ValidateFor(changed) == nil {
		t.Fatal("accepted substituted candidate")
	}
	r.Rules = r.Rules[:1]
	if r.ValidateFor(input) == nil {
		t.Fatal("incomplete catalog")
	}
}

func TestManagedImpactRejectsOfflineApplicationAttribution(t *testing.T) {
	now := time.Now().UTC()
	p := managed.DefaultPolicy("agent-a", "enrollment-a", 1, now)
	q := p
	q.Revision++
	q.Applications = []managed.ApplicationPolicy{{
		Service: "nginx.service", PolicyID: "web-observe", PolicyVersion: 1,
		Detection: managed.DetectionPolicy{Enabled: true, WebServices: []string{"nginx.service"}, Shells: []string{"sh"}},
		Response:  p.Response,
	}}
	for _, pair := range [][2]managed.Policy{{p, q}, {q, p}} {
		body, err := json.Marshal(managed.PolicyImpactInput{TrialID: "trial-app", EvaluatedAt: now, Current: pair[0], Candidate: pair[1]})
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "input.json")
		if err = os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
		var out, stderr bytes.Buffer
		err = run([]string{"rules", "compare", "--managed-input", path, "--host-config", "unused.yaml", "--events", "unused.jsonl"}, &out, &stderr)
		if err == nil || !strings.Contains(err.Error(), "offline comparison cannot verify application service membership") || out.Len() != 0 {
			t.Fatalf("expected offline comparison to reject application policy: %v", err)
		}
	}
}
