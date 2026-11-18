package agent

import (
	"context"
	"testing"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"xe-antishell/internal/config"
	"xe-antishell/internal/model"
	"xe-antishell/internal/storage"
)

func pairedSnapshot(id uint32) *model.CredentialSnapshot {
	p := func() *uint32 { v := id; return &v }
	yes := true
	level := int32(0)
	return &model.CredentialSnapshot{UID: p(), EUID: p(), GID: p(), EGID: p(), SUID: p(), SGID: p(), FSUID: p(), FSGID: p(), UserNamespace: &model.UserNamespace{Inum: 4026531837, IsHost: &yes, Level: &level}, Capabilities: &model.CredentialCapabilities{Effective: []string{}, Permitted: []string{}, Inheritable: []string{}}}
}
func pairedEvent() model.Event {
	zero := int64(0)
	now := time.Now().UTC()
	return model.Event{ID: "paired-global", SourceEventID: "paired-global-source", BootID: "boot-test", Source: "tetragon", Type: "process.credential_change", EventTime: now, IngestTime: now, Process: model.Process{PID: 711, TID: 712, ExecID: "test-current-exec", Exe: "/usr/bin/test-task", StartTime: now.Add(-time.Hour), UID: 0, EUID: 0, Credentials: pairedSnapshot(0)}, Credential: &model.CredentialObservation{Before: pairedSnapshot(1000), After: pairedSnapshot(0), TGID: 711, TID: 712, TaskStartTimeNS: 100, Evidence: model.CredentialEvidence, PolicyName: model.CredentialPolicyName, Function: "commit_creds", ReturnValue: &zero, Outcome: "applied"}}
}
func TestGlobalCredentialPipelineStoresPairedProofWithoutRewritingExecSnapshot(t *testing.T) {
	s, store := newTestService(t, config.CollectorDisabled, func(c *config.Config) {
		c.Detection.PrivilegeRules = true
		c.Collector.Tetragon.OnlyDetectionOrigins = true
		c.Collector.Tetragon.IncludeExecutables = []string{"sh"}
	})
	defer store.Close()
	enableTimestampDelivery(t, store)
	event := pairedEvent()
	if err := s.processEvent(context.Background(), &event); err != nil {
		t.Fatal(err)
	}
	saved, err := store.GetEvent(context.Background(), event.ID)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Process.EUID != 0 || *saved.Credential.Before.EUID != 1000 || *saved.Credential.After.EUID != 0 {
		t.Fatal("cached execution snapshot was used as transition proof")
	}
	fs, err := store.ListFindings(context.Background(), storage.FindingFilter{Limit: 10})
	if err != nil || len(fs) != 1 || fs[0].RuleID != "privilege-host-root-gain" || !fs[0].DetectionOnly {
		t.Fatalf("global credential finding unavailable: %#v %v", fs, err)
	}
	delivery, err := store.DeliveryStatus(context.Background())
	if err != nil || delivery.Pending != 1 {
		t.Fatalf("paired proof/finding did not share atomic outbox: %#v %v", delivery, err)
	}
	for _, mode := range []string{"would_block", "enforce"} {
		p := managed.DefaultPolicy("agent-test", "enrollment-test", 1, time.Now().UTC())
		p.Response.Mode = mode
		p.Response.Action = "terminate"
		p.Response.RiskThreshold = 1
		p.Response.MinConfidence = .01
		p.Response.RequiredCapabilities = []string{"observation.process_exec"}
		s.applyResponseDecisions(fs, &p)
		if fs[0].ResponseDecision != "detection_only" {
			t.Fatal("privilege finding became a response target", mode)
		}
		if err := s.executeResponses(context.Background(), event, fs, &p); err != nil {
			t.Fatal("detection-only observation touched response store", err)
		}
	}
}
func TestGlobalRootExecBypassesOnlyWebRetentionWhenOptedIn(t *testing.T) {
	for _, on := range []bool{false, true} {
		s, store := newTestService(t, config.CollectorDisabled, func(c *config.Config) {
			c.Detection.PrivilegeRules = on
			if on {
				c.Detection.RootExecAlerts = "all"
			}
			c.Collector.Tetragon.OnlyDetectionOrigins = true
			c.Collector.Tetragon.IncludeExecutables = []string{"sh"}
		})
		now := time.Now().UTC()
		e := model.Event{ID: "global-root", BootID: "boot-test", Source: "tetragon", Type: "process.exec", EventTime: now, IngestTime: now, Process: model.Process{PID: 731, PPID: 1, ExecID: "global-root-exec", Exe: "/usr/bin/true", UID: 0, EUID: 0, StartTime: now.Add(-time.Second)}}
		if err := s.processEvent(context.Background(), &e); err != nil {
			t.Fatal(err)
		}
		events, err := store.ListEvents(context.Background(), storage.EventFilter{Limit: 10})
		if err != nil {
			t.Fatal(err)
		}
		if (len(events) == 1) != on {
			t.Fatalf("root retention opt-in changed: enabled=%v count=%d", on, len(events))
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
func TestCredentialUnknownEvidenceStoredButNotPromotedAndWrongTaskRejected(t *testing.T) {
	s, store := newTestService(t, config.CollectorDisabled, func(c *config.Config) { c.Detection.PrivilegeRules = true })
	defer store.Close()
	e := pairedEvent()
	e.Credential.Before = nil
	e.Credential.Outcome = "unknown"
	if err := s.processEvent(context.Background(), &e); err != nil {
		t.Fatal(err)
	}
	fs, err := store.ListFindings(context.Background(), storage.FindingFilter{Limit: 10})
	if err != nil || len(fs) != 0 {
		t.Fatal("unknown proof produced finding", err)
	}
	wrong := pairedEvent()
	wrong.Process.PID++
	if err := s.processEvent(context.Background(), &wrong); err == nil {
		t.Fatal("credential evidence attached to a different task")
	}
}
func TestQueuedCredentialSnapshotsOwnAllPointerAndCapabilityData(t *testing.T) {
	s, store := newTestService(t, config.CollectorDisabled, nil)
	defer store.Close()
	s.accepting = true
	e := pairedEvent()
	e.Process.Credentials.Capabilities.Effective = []string{"CAP_SETUID"}
	if err := s.Submit(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	*e.Credential.Before.EUID = 0
	*e.Process.Credentials.EUID = 1000
	e.Process.Credentials.Capabilities.Effective[0] = "CAP_SYS_ADMIN"
	*e.Credential.After.UserNamespace.IsHost = false
	queued := <-s.eventQueue
	if *queued.Credential.Before.EUID != 1000 || *queued.Process.Credentials.EUID != 0 || queued.Process.Credentials.Capabilities.Effective[0] != "CAP_SETUID" || queued.Credential.After.UserNamespace.Scope() != "host" {
		t.Fatal("caller mutated queued credential evidence")
	}
}

func TestCredentialReceiptKeepsSourceTimeAcrossQueueDelay(t *testing.T) {
	s, store := newTestService(t, config.CollectorDisabled, nil)
	defer store.Close()
	e := pairedEvent()
	old := time.Now().UTC().Add(-time.Minute)
	e.EventTime = old
	e.IngestTime = old.Add(time.Second)
	s.recordRuntimeEvent(e, 0)
	got := s.runtimeEvidence["tetragon"].CredentialAt
	if !got.Equal(old) {
		t.Fatal("delayed queued credential receipt became fresh", got)
	}
	e.EventTime = old.Add(-time.Hour)
	e.IngestTime = old.Add(time.Second)
	s.recordRuntimeEvent(e, 0)
	if !s.runtimeEvidence["tetragon"].CredentialAt.Equal(got) {
		t.Fatal("out of order event overwrote latest valid evidence")
	}
	e.EventTime = time.Now().Add(time.Hour)
	e.IngestTime = e.EventTime
	s.recordRuntimeEvent(e, 0)
	if !s.runtimeEvidence["tetragon"].CredentialAt.Equal(got) {
		t.Fatal("future source event established fresh evidence")
	}
}
