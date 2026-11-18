package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"xe-antishell/internal/capability"
	"xe-antishell/internal/collector"
	"xe-antishell/internal/config"
	"xe-antishell/internal/model"
	"xe-antishell/internal/storage"
)

func operationFixture(t *testing.T, kind string, ingest time.Time) model.Event {
	t.Helper()
	sourceTime := time.Date(2026, 11, 17, 0, 0, 1, 0, time.UTC)
	process := map[string]any{"exec_id": "operation-child", "parent_exec_id": "operation-parent", "pid": 711, "binary": "/usr/bin/python3", "start_time": sourceTime.Add(-time.Second), "arguments": "PRIVATE_CODE_MUST_NOT_BE_STORED"}
	parent := map[string]any{"exec_id": "operation-parent", "pid": 710, "binary": "/usr/sbin/nginx", "start_time": sourceTime.Add(-time.Hour)}
	body := map[string]any{"process": process, "parent": parent, "action": "KPROBE_ACTION_POST"}
	envelope := map[string]any{"time": sourceTime}
	switch kind {
	case "process.exec_observation":
		body["policy_name"] = "xeas-exec-python-c-v1"
		body["subsys"] = "sched"
		body["event"] = "sched_process_exec"
		envelope["process_tracepoint"] = body
	case "file.write":
		body["policy_name"] = "xeas-file-write-v1"
		body["function_name"] = "vfs_write"
		body["args"] = []any{map[string]any{"label": "target", "file_arg": map[string]any{"path": "/var/www/example.php"}}}
		body["return"] = map[string]any{"long_arg": "5"}
		envelope["process_kprobe"] = body
	case "network.connect":
		body["policy_name"] = "xeas-network-connect-v1"
		body["function_name"] = "tcp_v4_connect"
		body["args"] = []any{map[string]any{"label": "destination", "sockaddr_arg": map[string]any{"family": "AF_INET", "addr": "192.0.2.5", "port": 443}}}
		body["return"] = map[string]any{"int_arg": 0}
		envelope["process_kprobe"] = body
	default:
		t.Fatal("unknown fixture")
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	event, err := collector.NormalizeTetragonJSON(raw, ingest, collector.Metadata{BootID: "boot-test", HostID: "host-test"})
	if err != nil {
		t.Fatal(err)
	}
	return event
}

func TestOperationObservationPipelinePersistsTypedEvidenceAndOutbox(t *testing.T) {
	service, store := newTestService(t, config.CollectorDisabled, func(c *config.Config) { c.Detection.ExtendedProcessRules = true; c.Privacy.StoreRawEvents = true })
	defer store.Close()
	enableTimestampDelivery(t, store)
	ctx := context.Background()
	now := time.Date(2026, 11, 17, 0, 0, 2, 0, time.UTC)
	for _, kind := range []string{"process.exec_observation", "file.write", "network.connect"} {
		event := operationFixture(t, kind, now)
		if err := service.processEvent(ctx, &event); err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		stored, err := store.GetEvent(ctx, event.ID)
		if err != nil {
			t.Fatal(err)
		}
		encoded, _ := json.Marshal(stored)
		if bytes.Contains(encoded, []byte("PRIVATE_CODE")) || len(stored.Process.Argv) != 0 || len(stored.RawJSON) != 0 {
			t.Fatalf("%s leaked source contents", kind)
		}
		if stored.Type != kind || stored.Process.ExecID != "operation-child" {
			t.Fatal("typed evidence lost process identity")
		}
	}
	findings, err := store.ListFindings(ctx, storage.FindingFilter{Limit: 10})
	if err != nil || len(findings) != 1 || findings[0].RuleID != "web-descendant-inline-interpreter" || !findings[0].DetectionOnly {
		t.Fatalf("operation findings must stay limited to the explicit execution rule: %+v %v", findings, err)
	}
	bundles, _ := timestampBundles(t, store)
	if len(bundles) != 3 {
		t.Fatalf("typed events not delivered: %d", len(bundles))
	}
	for _, b := range bundles {
		raw, _ := json.Marshal(b)
		if bytes.Contains(raw, []byte("PRIVATE_CODE")) {
			t.Fatal("outbox leaked code")
		}
	}
}

func TestDelayedOperationAndRetryDoNotResurrectExitedProcess(t *testing.T) {
	service, store := newTestService(t, config.CollectorDisabled, nil)
	defer store.Close()
	enableTimestampDelivery(t, store)
	ctx := context.Background()
	now := time.Date(2026, 11, 17, 0, 0, 2, 0, time.UTC)
	first := operationFixture(t, "file.write", now)
	if err := service.processEvent(ctx, &first); err != nil {
		t.Fatal(err)
	}
	exit := model.Event{SchemaVersion: model.SchemaVersion, ID: "operation-exit", SourceEventID: "operation-exit", Type: "process.exit", Source: "tetragon", BootID: first.BootID, HostID: first.HostID, EventTime: now.Add(time.Second), IngestTime: now.Add(2 * time.Second), Process: first.Process}
	if err := service.processEvent(ctx, &exit); err != nil {
		t.Fatal(err)
	}
	retry := operationFixture(t, "file.write", now.Add(3*time.Second))
	if err := service.processEvent(ctx, &retry); err != nil {
		t.Fatalf("operation retry conflicted after exit: %v", err)
	}
	process, err := store.GetProcess(ctx, first.Process.Key)
	if err != nil || process.ExitedAt == nil || !process.ExitedAt.Equal(exit.EventTime) {
		t.Fatalf("exit lost after context observation: %+v %v", process, err)
	}
	if _, current := service.lineage.CurrentByPID(process.PID); current {
		t.Fatal("operation revived an exited process")
	}
	original, err := store.GetEvent(ctx, first.ID)
	if err != nil || original.Process.ExitedAt != nil {
		t.Fatal("retry rewrote original evidence")
	}
	bundles, _ := timestampBundles(t, store)
	if len(bundles) != 2 {
		t.Fatalf("retry duplicated delivery: %d", len(bundles))
	}
}

func TestOperationRetentionRequiresWebOriginIndependentlyOfExecFilters(t *testing.T) {
	service, store := newTestService(t, config.CollectorDisabled, func(c *config.Config) { c.Collector.Tetragon.IncludeExecutables = []string{"sh"} })
	defer store.Close()
	ctx := context.Background()
	event := operationFixture(t, "file.write", time.Now().UTC())
	if err := service.processEvent(ctx, &event); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetEvent(ctx, event.ID); err != nil {
		t.Fatalf("legacy shell filter hid an explicitly configured file observation: %v", err)
	}
	other := operationFixture(t, "network.connect", time.Now().UTC())
	other.Process.ExecID = "unrelated"
	other.Process.Key = "unrelated"
	other.Process.ParentKey = ""
	other.Process.PPID = -1
	other.Ancestors = nil
	other.Process.Exe = "/usr/bin/worker"
	other.ID = "unrelated-network"
	other.SourceEventID = "unrelated-network"
	if err := service.processEvent(ctx, &other); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetEvent(ctx, other.ID); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("unrelated service operation retained: %v", err)
	}
}

func TestOperationValidationRejectsFalseSuccessAndUntrustedExecutionProof(t *testing.T) {
	cases := []struct {
		name   string
		change func(*model.Event)
	}{
		{"TCP is not established", func(e *model.Event) { e.Network.Outcome = "established" }},
		{"wrong family", func(e *model.Event) { e.Network.Family = "ipv6" }},
		{"wrong address", func(e *model.Event) { e.Network.DestinationAddress = "not-an-ip" }},
		{"missing process identity", func(e *model.Event) { e.Process.ExecID = "" }},
		{"two payloads", func(e *model.Event) { e.File = &model.FileObservation{} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := operationFixture(t, "network.connect", time.Now().UTC())
			tc.change(&e)
			if err := validateOperationEvent(e); err == nil {
				t.Fatal("invalid observation accepted")
			}
		})
	}
	e := operationFixture(t, "process.exec_observation", time.Now().UTC())
	e.Execution.PolicyName = "untrusted-policy"
	if err := validateOperationEvent(e); err == nil {
		t.Fatal("untrusted policy proof accepted")
	}
}

func TestOperationRuntimeCapabilitiesNeedTheirOwnValidatedEvidence(t *testing.T) {
	service, store := newTestService(t, config.CollectorDisabled, nil)
	defer store.Close()
	service.report.Capabilities = make(map[string]model.Capability)
	prepareRuntimeReport(service)
	setTestCollector(service, &runtimeTestCollector{health: collector.HealthSnapshot{Name: "tetragon-json", Running: true}})
	service.setRuntimeState(model.AgentModeActive, model.HealthHealthy, "tetragon-json", nil)
	service.recordRuntimeEvent(model.Event{Type: "process.exec", Source: "tetragon", Process: model.Process{PID: 1, Exe: "/usr/sbin/nginx"}}, 0)
	before, _ := service.Capabilities(context.Background())
	if before.Capabilities[capability.FileCapability].RuntimeState == "active" {
		t.Fatal("exec proof falsely enabled file observation")
	}
	for _, kind := range []string{"file.write", "network.connect", "process.exec_observation"} {
		e := operationFixture(t, kind, time.Now().UTC())
		if err := service.processEvent(context.Background(), &e); err != nil {
			t.Fatal(err)
		}
	}
	after, _ := service.Capabilities(context.Background())
	for _, name := range []string{capability.FileCapability, capability.NetworkCapability, capability.InterpreterCapability} {
		c := after.Capabilities[name]
		if c.RuntimeState != "active" || c.VerifiedAt == nil || c.Implementation != "implemented" {
			t.Fatalf("real operation not reported: %+v", c)
		}
	}
	setTestCollector(service, &runtimeTestCollector{health: collector.HealthSnapshot{Name: "tetragon-json", Running: false}})
	stopped, _ := service.Capabilities(context.Background())
	for _, name := range []string{capability.FileCapability, capability.NetworkCapability, capability.InterpreterCapability} {
		if stopped.Capabilities[name].RuntimeState == "active" {
			t.Fatal("stopped stream retained an active observation capability")
		}
	}
}
