package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"xe-antishell/internal/capability"
	"xe-antishell/internal/config"
	"xe-antishell/internal/model"
)

// Run the real JSON adapter against a local command and a temporary agent DB.
// The script's first argument is a private directory shared with the test.
func startRecoveryFixture(t *testing.T, mode config.CollectorMode, script string) (*Service, string) {
	t.Helper()
	dir := t.TempDir()
	cfg, store, prober := newTestDependencies(t, mode, func(cfg *config.Config) {
		cfg.Collector.Tetragon.Command = "/bin/sh"
		cfg.Collector.Tetragon.Args = []string{"-c", script, "tetra-fixture", dir}
		cfg.Collector.Tetragon.IncludeExecutables = []string{"kept"}
	})
	t.Cleanup(func() { store.Close() })
	prober.report.Capabilities[capability.TetragonCapability] = model.Capability{
		Name: capability.TetragonCapability, State: model.CapabilityLimited,
	}
	service, err := NewWithProcessSource(cfg, store, prober, staticProcessSource{})
	if err != nil {
		t.Fatal(err)
	}
	startService(t, service)
	t.Cleanup(func() { shutdownService(t, service) })
	return service, dir
}

func TestTetragonReconnectPersistsEventsAndReportsGap(t *testing.T) {
	firstTime := time.Now().UTC().Format(time.RFC3339Nano)
	service, dir := startRecoveryFixture(t, config.CollectorAuto, `
set -eu
printf x >> "$1/starts"
first_frame='{"time":"`+firstTime+`","process_exec":{"process":{"pid":81,"exec_id":"first","parent_exec_id":"parent","uid":1000,"binary":"/usr/bin/kept"}}}'
if [ ! -e "$1/end-first" ]; then
  echo "$first_frame"
  while [ ! -e "$1/end-first" ]; do sleep 0.02; done
  exit 0
fi
echo '{"process_exec":{"process":{"pid":82,"exec_id":"filtered","uid":1000,"binary":"/usr/bin/filtered"}}}'
while [ ! -e "$1/emit-duplicate" ]; do sleep 0.02; done
echo "$first_frame"
echo '{"process_exec":{"process":{"pid":84,"exec_id":"after-duplicate","uid":1000,"binary":"/usr/bin/filtered"}}}'
while [ ! -e "$1/emit-kept" ]; do sleep 0.02; done
echo '{"process_exec":{"process":{"pid":83,"exec_id":"recovered","uid":1000,"binary":"/usr/bin/kept"}}}'
exec sleep 60
`)
	ctx := context.Background()
	status := func() model.AgentStatus {
		t.Helper()
		s, err := service.Status(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	events := func() []model.Event {
		t.Helper()
		rows, err := service.ListEvents(ctx, 10)
		if err != nil {
			t.Fatal(err)
		}
		return rows
	}
	signal := func(name string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	waitFor(t, func() bool {
		s := status()
		return s.Health == model.HealthHealthy && len(events()) == 1 &&
			s.CapabilityReport.Capabilities[capability.ProcessLineageCapability].RuntimeState == "active"
	})
	first := status()
	signal("end-first")
	waitFor(t, func() bool {
		_, processed := service.lineage.CurrentByPID(82)
		return processed
	})
	pending := status()
	details := pending.CapabilityReport.Capabilities[capability.TetragonCapability].Details
	start := details["last_disconnect_at"]
	disconnected, err := time.Parse(time.RFC3339Nano, start)
	if err != nil || details["last_recovered_at"] != "" || details["reconnect_attempts"] != "1" || len(events()) != 1 {
		t.Fatalf("reconnected stream with only a filtered event should have an open gap: %v", details)
	}
	if pending.CapabilityReport.Capabilities[capability.ProcessLineageCapability].RuntimeState == "active" {
		t.Fatal("new subscription inherited lineage evidence from the first subscription")
	}
	signal("emit-duplicate")
	waitFor(t, func() bool {
		// This filtered marker follows the duplicate in the same FIFO queue.
		_, processed := service.lineage.CurrentByPID(84)
		return processed
	})
	duplicate := status()
	details = duplicate.CapabilityReport.Capabilities[capability.TetragonCapability].Details
	if details["last_recovered_at"] != "" || details["last_disconnect_at"] != start ||
		duplicate.Dropped != 0 || len(events()) != 1 || duplicate.CollectorHealth == nil || duplicate.CollectorHealth.EventsReceived != 4 {
		t.Fatalf("idempotent redelivery must preserve the open gap and single stored row: status=%+v, details=%v", duplicate, details)
	}
	signal("emit-kept")
	waitFor(t, func() bool {
		return status().CapabilityReport.Capabilities[capability.TetragonCapability].Details["last_recovered_at"] != ""
	})
	recovered := status()
	details = recovered.CapabilityReport.Capabilities[capability.TetragonCapability].Details
	end, err := time.Parse(time.RFC3339Nano, details["last_recovered_at"])
	if err != nil || end.Before(disconnected) || details["last_disconnect_at"] != start {
		t.Fatalf("invalid recovered interval: %v", details)
	}
	if recovered.Health != model.HealthHealthy || recovered.Mode != model.AgentModeActive || recovered.StartedAt != first.StartedAt ||
		recovered.Collector != "tetragon-json" || recovered.CollectorHealth == nil || !recovered.CollectorHealth.Running || recovered.CollectorHealth.EventsReceived != 5 {
		t.Fatalf("unexpected recovered status or source counters: %+v, source=%+v", recovered, recovered.CollectorHealth)
	}
	if recovered.CapabilityReport.Capabilities[capability.ProcessExecCapability].RuntimeState != "active" {
		t.Fatal("new execution receipt did not restore the execution capability")
	}
	rows := events()
	if len(rows) != 2 || rows[0].Process.ExecID != "recovered" || rows[1].Process.ExecID != "first" || rows[0].Sequence <= rows[1].Sequence {
		t.Fatalf("agent did not retain both observations in sequence: %+v", rows)
	}
	starts, err := os.ReadFile(filepath.Join(dir, "starts"))
	if err != nil || string(starts) != "xx" {
		t.Fatalf("wanted exactly two subscriptions, got %q: %v", starts, err)
	}
}

func TestTetragonShutdownCancelsReconnectBackoff(t *testing.T) {
	service, dir := startRecoveryFixture(t, config.CollectorTetragon, `
set -eu
printf x >> "$1/starts"
if [ -e "$1/first" ]; then
  while [ ! -e "$1/end-second" ]; do sleep 0.02; done
fi
: > "$1/first"
exit 9
`)
	start := ""
	waitFor(t, func() bool {
		s, _ := service.Status(context.Background())
		start = s.CapabilityReport.Capabilities[capability.TetragonCapability].Details["last_disconnect_at"]
		return start != "" && s.CollectorHealth != nil && s.CollectorHealth.Running
	})
	if err := os.WriteFile(filepath.Join(dir, "end-second"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		s, _ := service.Status(context.Background())
		details := s.CapabilityReport.Capabilities[capability.TetragonCapability].Details
		return !s.CollectorHealth.Running && details["last_recovered_at"] == "" && details["last_disconnect_at"] == start
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := service.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown waited for reconnect backoff: %v", err)
	}
	starts, err := os.ReadFile(filepath.Join(dir, "starts"))
	if err != nil || string(starts) != "xx" {
		t.Fatalf("unexpected collector restart during shutdown: %q %v", starts, err)
	}
}
