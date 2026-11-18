package agent

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"xe-antishell/internal/capability"
	"xe-antishell/internal/config"
	"xe-antishell/internal/model"
	"xe-antishell/internal/storage"
)

type staticProber struct {
	report model.CapabilityReport
}

// Direct-input fixtures use the initial subscription generation.
func (s *Service) processEvent(ctx context.Context, event *model.Event) error {
	return s.processObservation(ctx, event, 0, time.Time{}, time.Now())
}

func (p staticProber) Probe(context.Context) (model.CapabilityReport, error) { return p.report, nil }

type staticProcessSource struct {
	processes   []model.Process
	origin      string
	snapshotErr error
}

func (s staticProcessSource) Snapshot(context.Context, string) ([]model.Process, error) {
	return append([]model.Process(nil), s.processes...), s.snapshotErr
}

func (s staticProcessSource) OriginService(context.Context, int) (string, error) {
	if s.origin == "" {
		return "", errors.New("origin service unavailable")
	}
	return s.origin, nil
}

func TestInvalidEventDoesNotPoisonRuntimeState(t *testing.T) {
	service, store := newTestService(t, config.CollectorDisabled, nil)
	startService(t, service)

	if err := service.Submit(context.Background(), model.Event{Source: "test"}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		status, _ := service.Status(context.Background())
		return status.ParseErrors == 1
	})
	status, err := service.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.Mode != model.AgentModeUnsupported || status.Health != model.HealthDegraded {
		t.Fatalf("invalid event changed runtime state: %#v", status)
	}
	if status.LastError != "" {
		t.Fatalf("invalid input became a runtime failure: %q", status.LastError)
	}
	shutdownService(t, service)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestShutdownDrainsAcceptedEvents(t *testing.T) {
	service, store := newTestService(t, config.CollectorDisabled, func(cfg *config.Config) {
		cfg.Limits.QueueSize = 256
	})
	startService(t, service)
	const count = 200
	for index := 0; index < count; index++ {
		if err := service.Submit(context.Background(), model.Event{
			Type: "security.test", Source: "test", EventTime: time.Now().UTC(),
		}); err != nil {
			t.Fatalf("submit event %d: %v", index, err)
		}
	}
	shutdownService(t, service)
	events, err := store.ListEvents(context.Background(), storage.EventFilter{Limit: count})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != count {
		t.Fatalf("shutdown retained %d/%d accepted events", len(events), count)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestShutdownDirectlyFlushesPendingAuditGroup(t *testing.T) {
	service, store := newTestService(t, config.CollectorAudit, nil)
	startService(t, service)
	lines := []string{
		`type=SYSCALL msg=audit(1700000000.100:77): arch=c000003e syscall=59 pid=123 ppid=1 uid=1000 euid=1000 gid=1000 egid=1000 exe="/bin/sh"`,
		`type=EXECVE msg=audit(1700000000.100:77): argc=1 a0="sh"`,
	}
	for _, line := range lines {
		if err := service.SubmitAuditLine(context.Background(), []byte(line)); err != nil {
			t.Fatal(err)
		}
	}
	shutdownService(t, service)
	events, err := store.ListEvents(context.Background(), storage.EventFilter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Source != "audit" || events[0].Process.PID != 123 {
		t.Fatalf("pending audit group was not durably flushed: %#v", events)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestNormalizationPreservesValidJSONAndUTF8(t *testing.T) {
	service, store := newTestService(t, config.CollectorDisabled, func(cfg *config.Config) {
		cfg.Limits.MaxRawJSON = 8
		cfg.Limits.MaxArgument = 2
		cfg.Privacy.StoreRawEvents = true
	})
	startService(t, service)
	raw := json.RawMessage(`{"value":"too long"}`)
	if err := service.Submit(context.Background(), model.Event{
		Type: "process.exec", Source: "test", EventTime: time.Now().UTC(), RawJSON: raw,
		Process: model.Process{PID: 44, PPID: 1, Exe: "/bin/sh", Argv: []string{"€"}},
	}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		events, _ := store.ListEvents(context.Background(), storage.EventFilter{Limit: 1})
		return len(events) == 1
	})
	shutdownService(t, service)
	events, err := store.ListEvents(context.Background(), storage.EventFilter{Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	event := events[0]
	if event.RawJSON != nil {
		t.Fatalf("oversized raw JSON should be removed, got %s", event.RawJSON)
	}
	if len(event.Process.Argv) != 1 || !utf8.ValidString(event.Process.Argv[0]) {
		t.Fatalf("argv is not valid UTF-8: %#v", event.Process.Argv)
	}
	if !contains(event.TruncatedFields, "raw_json") || !contains(event.TruncatedFields, "process.argv") {
		t.Fatalf("truncation was not disclosed: %#v", event.TruncatedFields)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSequenceContinuesAfterRestart(t *testing.T) {
	cfg, store, prober := newTestDependencies(t, config.CollectorDisabled, nil)
	first, err := NewWithProcessSource(cfg, store, prober, staticProcessSource{})
	if err != nil {
		t.Fatal(err)
	}
	startService(t, first)
	if err := first.Submit(context.Background(), model.Event{Type: "security.test", Source: "test", EventTime: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		events, _ := store.ListEvents(context.Background(), storage.EventFilter{Limit: 10})
		return len(events) == 1
	})
	shutdownService(t, first)

	second, err := NewWithProcessSource(cfg, store, prober, staticProcessSource{})
	if err != nil {
		t.Fatal(err)
	}
	startService(t, second)
	if err := second.Submit(context.Background(), model.Event{Type: "security.test", Source: "test", EventTime: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	shutdownService(t, second)
	events, err := store.ListEvents(context.Background(), storage.EventFilter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].Sequence != 2 || events[1].Sequence != 1 {
		t.Fatalf("sequence did not continue across restart: %#v", events)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRestartFallsBackToDurableLineageForDetection(t *testing.T) {
	cfg, store, prober := newTestDependencies(t, config.CollectorDisabled, nil)
	first, err := NewWithProcessSource(cfg, store, prober, staticProcessSource{})
	if err != nil {
		t.Fatal(err)
	}
	startService(t, first)
	parentTime := time.Now().UTC()
	if err := first.Submit(context.Background(), model.Event{
		Type: "process.exec", Source: "test", EventTime: parentTime,
		Process: model.Process{PID: 700, PPID: 1, Exe: "/usr/sbin/php-fpm", UID: 991, EUID: 991},
	}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		_, err := store.FindLatestProcessByPID(context.Background(), "boot-test", 700)
		return err == nil
	})
	shutdownService(t, first)

	second, err := NewWithProcessSource(cfg, store, prober, staticProcessSource{snapshotErr: errors.New("proc unavailable")})
	if err != nil {
		t.Fatal(err)
	}
	startService(t, second)
	if err := second.Submit(context.Background(), model.Event{
		Type: "process.exec", Source: "test", EventTime: parentTime.Add(time.Second),
		Process: model.Process{PID: 701, PPID: 700, Exe: "/bin/bash", UID: 991, EUID: 991},
	}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		findings, _ := store.ListFindings(context.Background(), storage.FindingFilter{Limit: 10})
		return len(findings) == 1
	})
	shutdownService(t, second)
	findings, err := store.ListFindings(context.Background(), storage.FindingFilter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].RuleID != "web-descendant-shell" {
		t.Fatalf("restored lineage did not produce finding: %#v", findings)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSensitiveArgumentsAndRawPayloadAreRedactedByDefault(t *testing.T) {
	service, store := newTestService(t, config.CollectorDisabled, nil)
	startService(t, service)
	event := model.Event{
		Type: "process.exec", Source: "test", EventTime: time.Now().UTC(),
		RawJSON: json.RawMessage(`{"token":"raw-secret"}`),
		Process: model.Process{
			PID: 55, PPID: 1, Exe: "/usr/bin/tool",
			Argv: []string{"tool", "--password", "plain-secret", "token=abc", "Bearer xyz", "Authorization: Bearer nested"},
		},
	}
	if err := service.Submit(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		events, _ := store.ListEvents(context.Background(), storage.EventFilter{Limit: 1})
		return len(events) == 1
	})
	shutdownService(t, service)
	events, err := store.ListEvents(context.Background(), storage.EventFilter{Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	got := events[0]
	if got.RawJSON != nil {
		t.Fatalf("raw source payload was retained: %s", got.RawJSON)
	}
	want := []string{"tool", "--password", "[REDACTED]", "token=[REDACTED]", "Bearer [REDACTED]", "Authorization: [REDACTED]"}
	if strings.Join(got.Process.Argv, "|") != strings.Join(want, "|") {
		t.Fatalf("argv redaction = %#v, want %#v", got.Process.Argv, want)
	}
	if !contains(got.RedactedFields, "raw_json") || !contains(got.RedactedFields, "process.argv") {
		t.Fatalf("redactions were not disclosed: %#v", got.RedactedFields)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestWholeEventLimitAndSequenceRangeAreEnforced(t *testing.T) {
	service, store := newTestService(t, config.CollectorDisabled, func(cfg *config.Config) {
		cfg.Limits.MaxEventBytes = 1024
		cfg.Limits.MaxRawJSON = 128
		cfg.Limits.MaxArgument = 512
	})
	startService(t, service)
	oversized := model.Event{
		Type: "security.test", Source: "test", EventTime: time.Now().UTC(),
		Process: model.Process{Exe: strings.Repeat("x", 2048)},
	}
	if err := service.Submit(context.Background(), oversized); err != nil {
		t.Fatal(err)
	}
	if err := service.Submit(context.Background(), model.Event{
		Type: "security.test", Source: "test", EventTime: time.Now().UTC(), Sequence: math.MaxUint64,
	}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		status, _ := service.Status(context.Background())
		return status.ParseErrors == 2
	})
	if err := service.Submit(context.Background(), model.Event{
		Type: "security.test", Source: "test", EventTime: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	shutdownService(t, service)
	events, err := store.ListEvents(context.Background(), storage.EventFilter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Sequence != 1 {
		t.Fatalf("invalid inputs polluted durable events or sequence watermark: %#v", events)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestStartAndShutdownLifecycleGuards(t *testing.T) {
	service, store := newTestService(t, config.CollectorDisabled, nil)
	startService(t, service)
	if err := service.Start(context.Background()); err == nil || !strings.Contains(err.Error(), "already started") {
		t.Fatalf("expected duplicate start error, got %v", err)
	}
	shutdownService(t, service)
	shutdownService(t, service)
	if err := service.Start(context.Background()); err == nil || !strings.Contains(err.Error(), "cannot be restarted") {
		t.Fatalf("expected restart error, got %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestLiveProcessSnapshotSeedsExistingWebParent(t *testing.T) {
	cfg, store, prober := newTestDependencies(t, config.CollectorDisabled, nil)
	parentTime := time.Now().UTC().Add(-time.Hour)
	parent := model.Process{
		Key: "snapshot-parent", PID: 700, PPID: 1, Exe: "/usr/sbin/php-fpm",
		StartTime: parentTime, FirstSeen: parentTime, LastSeen: parentTime,
		UID: 991, EUID: 991, GID: 991, EGID: 991,
	}
	service, err := NewWithProcessSource(cfg, store, prober, staticProcessSource{processes: []model.Process{parent}})
	if err != nil {
		t.Fatal(err)
	}
	startService(t, service)
	if err := service.Submit(context.Background(), model.Event{
		Type: "process.exec", Source: "test", EventTime: time.Now().UTC(),
		Process: model.Process{PID: 701, PPID: 700, Exe: "/bin/bash", UID: 991, EUID: 991},
	}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		findings, _ := store.ListFindings(context.Background(), storage.FindingFilter{Limit: 10})
		return len(findings) == 1
	})
	shutdownService(t, service)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestExecEventUsesLiveOriginService(t *testing.T) {
	cfg, store, prober := newTestDependencies(t, config.CollectorDisabled, func(cfg *config.Config) {
		cfg.Detection.WebServices = append(cfg.Detection.WebServices, "payments.service")
	})
	service, err := NewWithProcessSource(cfg, store, prober, staticProcessSource{origin: "payments.service"})
	if err != nil {
		t.Fatal(err)
	}
	startService(t, service)
	if err := service.Submit(context.Background(), model.Event{
		Type: "process.exec", Source: "test", EventTime: time.Now().UTC(),
		Process: model.Process{PID: 801, PPID: 800, Exe: "/bin/sh", UID: 1000, EUID: 1000},
	}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		findings, _ := store.ListFindings(context.Background(), storage.FindingFilter{Limit: 10})
		return len(findings) == 1
	})
	shutdownService(t, service)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}

func newTestService(t *testing.T, mode config.CollectorMode, mutate func(*config.Config)) (*Service, *storage.Store) {
	t.Helper()
	cfg, store, prober := newTestDependencies(t, mode, mutate)
	service, err := NewWithProcessSource(cfg, store, prober, staticProcessSource{})
	if err != nil {
		t.Fatal(err)
	}
	return service, store
}

func newTestDependencies(t *testing.T, mode config.CollectorMode, mutate func(*config.Config)) (config.Config, *storage.Store, staticProber) {
	t.Helper()
	cfg := config.Default()
	cfg.Agent.DatabasePath = t.TempDir() + "/sentinel.db"
	cfg.Agent.SocketPath = t.TempDir() + "/sentinel.sock"
	cfg.Collector.Mode = mode
	if mutate != nil {
		mutate(&cfg)
	}
	store, err := storage.Open(context.Background(), cfg.Agent.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	report := model.CapabilityReport{
		ProbeVersion: capability.ProbeVersion,
		ProbedAt:     time.Now().UTC(),
		Platform:     model.Platform{BootID: "boot-test", Hostname: "host-test"},
		Capabilities: map[string]model.Capability{
			capability.AuditCapability: {Name: capability.AuditCapability, State: model.CapabilityLimited},
		},
	}
	return cfg, store, staticProber{report: report}
}

func startService(t *testing.T, service *Service) {
	t.Helper()
	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func shutdownService(t *testing.T, service *Service) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := service.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition was not met before timeout")
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
