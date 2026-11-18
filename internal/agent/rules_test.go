package agent

import (
	"context"
	"testing"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"xe-antishell/internal/config"
	"xe-antishell/internal/detection"
	"xe-antishell/internal/model"
)

func TestRulesUsesPublishedPolicyAndReceiptsFromSelectedSource(t *testing.T) {
	s, store := newTestService(t, config.CollectorDisabled, nil)
	defer store.Close()
	ctx := context.Background()
	catalog, err := s.Rules(ctx)
	if err != nil || catalog.PolicySource != "local" || catalog.PolicyRevision != 0 {
		t.Fatalf("local catalog %+v %v", catalog, err)
	}
	getRule := func(id string) model.RuleStatus {
		t.Helper()
		current, err := s.Rules(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range current.Rules {
			if r.ID == id {
				return r
			}
		}
		t.Fatalf("missing rule %q", id)
		return model.RuleStatus{}
	}
	if r := getRule("web-descendant-shell"); !r.Enabled || r.Response != "observe" || r.Sensors[0].State == "active" || r.Sensors[0].VerifiedAt != nil {
		t.Fatalf("local shell %+v", r)
	}
	policy := managed.DefaultPolicy("a", "e", 7, time.Now().Add(-time.Minute))
	policy.Response.Mode = "would_block"
	s.detectionState.Store(&detectionState{engine: s.detectionState.Load().engine, enabled: true, policy: &policy})
	s.status.Collector = "tetragon-json"
	at := time.Now().UTC()
	s.runtimeEvidence = map[string]sourceRuntimeEvidence{"tetragon": {ExecAt: at, InterpreterAt: at}}
	catalog, err = s.Rules(ctx)
	if err != nil || catalog.PolicySource != "managed" || catalog.PolicyRevision != 7 || catalog.Collector != "tetragon-json" {
		t.Fatalf("managed catalog %+v %v", catalog, err)
	}
	if r := getRule("web-descendant-shell"); r.Response != "would_block" || r.Sensors[0].State != "active" || r.Sensors[0].VerifiedAt == nil || !r.Sensors[0].VerifiedAt.Equal(at) {
		t.Fatalf("published signed mode and live source %+v", r)
	}
	expired := policy
	expired.ExpiresAt = at.Add(-time.Second)
	s.detectionState.Store(&detectionState{engine: s.detectionState.Load().engine, enabled: true, policy: &expired})
	if r := getRule("web-descendant-shell"); !r.Enabled || r.Response != "observe" {
		t.Fatalf("expired policy %+v", r)
	}
	opts := detection.Options{WebServices: []string{"nginx"}, Shells: []string{"sh"}, ExtendedProcessRules: true, PrivilegeRules: true}
	s.detectionState.Store(&detectionState{engine: detection.NewWithOptions(opts), enabled: true, policy: &policy})
	for id, wanted := range map[string]string{"web-descendant-shell": "active", "web-descendant-temporary-script": "inactive", "web-descendant-inline-interpreter": "active", "privilege-capability-gain": "inactive"} {
		r := getRule(id)
		if !r.Enabled || r.Response != "detection_only" || r.Sensors[0].State != wanted || (r.Sensors[0].VerifiedAt != nil) != (wanted == "active") {
			t.Fatalf("%s: %+v", id, r)
		}
	}
	s.status.Collector = "audit-dispatcher"
	r := getRule("web-descendant-temporary-script")
	if r.Sensors[0].State == "active" || r.Sensors[0].VerifiedAt != nil {
		t.Fatalf("receipts crossed collector identity %+v", r)
	}
	s.runtimeEvidence["audit"] = sourceRuntimeEvidence{InterpreterAt: at}
	r = getRule("web-descendant-temporary-script")
	if r.Sensors[0].State != "active" || r.Sensors[0].VerifiedAt == nil || !r.Sensors[0].VerifiedAt.Equal(at) {
		t.Fatalf("exact audit argv sensor inactive %+v", r)
	}
}
