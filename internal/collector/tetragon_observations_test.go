package collector

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"xe-antishell/internal/model"
)

const observationPrivateFixture = "SYNTHETIC_CODE_AND_ENV_NOT_FOR_STORAGE"

func observationFixture(policy string) map[string]any {
	process := map[string]any{"exec_id": "exec-child", "parent_exec_id": "exec-parent", "pid": 42, "binary": "/usr/bin/python3.11", "start_time": "2026-11-17T00:00:00Z", "arguments": observationPrivateFixture, "environment_variables": []any{map[string]any{"Key": "PRIVATE_FIXTURE", "Value": observationPrivateFixture}}}
	parent := map[string]any{"exec_id": "exec-parent", "pid": 41, "binary": "/usr/sbin/php-fpm", "start_time": "2026-11-16T00:00:00Z", "arguments": observationPrivateFixture}
	return map[string]any{"time": "2026-11-17T00:00:01Z", "process_tracepoint": map[string]any{"process": process, "parent": parent, "ancestors": []any{parent}, "subsys": "sched", "event": "sched_process_exec", "policy_name": policy, "action": "KPROBE_ACTION_POST"}}
}

func normalizeObservationFixture(t *testing.T, fixture map[string]any, offset time.Duration) (model.Event, error) {
	t.Helper()
	raw, err := json.Marshal(fixture)
	if err != nil {
		t.Fatal(err)
	}
	return NormalizeTetragonJSON(raw, time.Date(2026, 11, 17, 0, 0, 2, 0, time.UTC).Add(offset), Metadata{BootID: "boot", HostID: "host"})
}

func kprobeFixture(policy, function string, argument map[string]any, result any) map[string]any {
	fixture := observationFixture(policy)
	probe := fixture["process_tracepoint"].(map[string]any)
	delete(fixture, "process_tracepoint")
	fixture["process_kprobe"] = probe
	delete(probe, "subsys")
	delete(probe, "event")
	probe["function_name"] = function
	probe["args"] = []any{argument}
	if result != nil {
		probe["return"] = result
	}
	return fixture
}

func TestTetragonInlinePoliciesYieldCodeFreeIndependentObservations(t *testing.T) {
	for name, policy := range tetragonInlinePolicies {
		t.Run(name, func(t *testing.T) {
			fixture := observationFixture(name)
			probe := fixture["process_tracepoint"].(map[string]any)
			probe["process"].(map[string]any)["binary"] = "/usr/bin/" + policy.runtime
			event, err := normalizeObservationFixture(t, fixture, 0)
			if err != nil {
				t.Fatal(err)
			}
			if event.Type != "process.exec_observation" || event.Execution == nil || event.Execution.Runtime != policy.runtime || event.Execution.Option != policy.option || event.Execution.Mode != "inline" || event.Execution.Evidence != "tetragon_policy" || event.Execution.PolicyName != name {
				t.Fatalf("wrong typed invocation evidence: %+v", event.Execution)
			}
			if event.Process.Key == "" || event.Process.ParentKey == "" || event.Process.LineageConfidence != model.LineageVerified || len(event.Ancestors) != 1 {
				t.Fatal("source process/parent identity was lost")
			}
			if !event.Process.FirstSeen.Equal(event.IngestTime) || !event.Ancestors[0].FirstSeen.Equal(event.IngestTime) {
				t.Fatal("source lifecycle time leaked into observation times")
			}
			encoded, _ := json.Marshal(event)
			if len(event.RawJSON) != 0 || len(event.Process.Argv) != 0 || len(event.Ancestors[0].Argv) != 0 || strings.Contains(string(encoded), observationPrivateFixture) {
				t.Fatal("code, environment or raw arguments reached durable evidence")
			}
			retry, err := normalizeObservationFixture(t, fixture, time.Minute)
			if err != nil || event.ID != retry.ID || event.SourceEventID != retry.SourceEventID {
				t.Fatalf("ingest retry changed source identity: %v", err)
			}
		})
	}
}

func TestTetragonObservationRejectsUntrustedPolicyOrIdentity(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(map[string]any)
	}{
		{"unknown policy", func(p map[string]any) { p["policy_name"] = "other-policy" }},
		{"wrong hook", func(p map[string]any) { p["event"] = "sys_enter_execve" }},
		{"missing exec id", func(p map[string]any) { delete(p["process"].(map[string]any), "exec_id") }},
		{"missing pid", func(p map[string]any) { delete(p["process"].(map[string]any), "pid") }},
		{"missing start", func(p map[string]any) { delete(p["process"].(map[string]any), "start_time") }},
		{"wrong binary", func(p map[string]any) { p["process"].(map[string]any)["binary"] = "/usr/bin/python-wrapper" }},
		{"conflicting parent", func(p map[string]any) { p["parent"].(map[string]any)["exec_id"] = "other-parent" }},
		{"enforcement action", func(p map[string]any) { p["action"] = "KPROBE_ACTION_SIGKILL" }},
		{"argument payload", func(p map[string]any) { p["args"] = []any{map[string]any{"string_arg": observationPrivateFixture}} }},
		{"data payload", func(p map[string]any) { p["data"] = []any{map[string]any{"bytes_arg": observationPrivateFixture}} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := observationFixture("xeas-exec-python-c-v1")
			test.change(fixture["process_tracepoint"].(map[string]any))
			if _, err := normalizeObservationFixture(t, fixture, 0); !errors.Is(err, ErrUnsupportedEvent) {
				t.Fatalf("unsupported observation error=%v", err)
			}
		})
	}
}

func TestTetragonFileWriteUsesActualReturnValue(t *testing.T) {
	for _, test := range []struct {
		name    string
		result  any
		outcome string
		value   int64
	}{
		{"written", map[string]any{"long_arg": "17", "label": "result"}, "written", 17},
		{"zero", map[string]any{"long_arg": "0"}, "no_data", 0},
		{"failed", map[string]any{"long_arg": -13}, "failed", -13},
		{"unknown", nil, "unknown", 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := kprobeFixture(tetragonFilePolicy, "vfs_write", map[string]any{"file_arg": map[string]any{"path": "/tmp/observed-file", "permission": "-rw-------"}, "label": "target"}, test.result)
			event, err := normalizeObservationFixture(t, fixture, 0)
			if err != nil {
				t.Fatal(err)
			}
			if event.Type != "file.write" || event.File == nil || event.File.Operation != "write" || event.File.Outcome != test.outcome || event.File.Path != "/tmp/observed-file" {
				t.Fatalf("file result: %+v", event.File)
			}
			if test.result == nil {
				if event.File.ReturnValue != nil {
					t.Fatal("missing return became success")
				}
			} else if event.File.ReturnValue == nil || *event.File.ReturnValue != test.value {
				t.Fatal("source return changed")
			}
			encoded, _ := json.Marshal(event)
			if strings.Contains(string(encoded), observationPrivateFixture) || len(event.RawJSON) != 0 {
				t.Fatal("file event retained source arguments")
			}
		})
	}
	for _, path := range []string{"relative", "/tmp/../etc/file", strings.Repeat("/a", 2050)} {
		fixture := kprobeFixture(tetragonFilePolicy, "vfs_write", map[string]any{"file_arg": map[string]any{"path": path}}, nil)
		if _, err := normalizeObservationFixture(t, fixture, 0); !errors.Is(err, ErrUnsupportedEvent) {
			t.Fatal("invalid file path accepted")
		}
	}
	fixture := kprobeFixture(tetragonFilePolicy, "security_file_permission", map[string]any{"file_arg": map[string]any{"path": "/tmp/file"}}, map[string]any{"int_arg": 0})
	if _, err := normalizeObservationFixture(t, fixture, 0); !errors.Is(err, ErrUnsupportedEvent) {
		t.Fatal("permission check became an actual write")
	}
}

func TestTetragonNetworkConnectUsesRequestedSockaddr(t *testing.T) {
	for _, test := range []struct{ function, family, address string }{
		{"tcp_v4_connect", "AF_INET", "192.0.2.8"}, {"tcp_v6_connect", "AF_INET6", "2001:db8::8"},
	} {
		for _, result := range []any{nil, map[string]any{"int_arg": 0}, map[string]any{"int_arg": -111}} {
			fixture := kprobeFixture(tetragonNetworkPolicy, test.function, map[string]any{"sockaddr_arg": map[string]any{"family": test.family, "addr": test.address, "port": 8443}, "label": "destination"}, result)
			event, err := normalizeObservationFixture(t, fixture, 0)
			if err != nil {
				t.Fatal(err)
			}
			if event.Type != "network.connect" || event.Network == nil || event.Network.Protocol != "tcp" || event.Network.DestinationAddress != test.address || event.Network.DestinationPort != 8443 {
				t.Fatalf("network fields: %+v", event.Network)
			}
			want := "unknown"
			if result != nil {
				want = "initiated"
				if result.(map[string]any)["int_arg"].(int) < 0 {
					want = "failed"
				}
			}
			if event.Network.Outcome != want || event.Network.Outcome == "established" {
				t.Fatalf("return misreported connection completion: %+v", event.Network)
			}
		}
	}
	for _, argument := range []map[string]any{
		{"sock_arg": map[string]any{"family": "AF_INET", "daddr": "192.0.2.8", "dport": 80}},
		{"sockaddr_arg": map[string]any{"family": "AF_INET6", "addr": "192.0.2.8", "port": 80}},
		{"sockaddr_arg": map[string]any{"family": "AF_INET", "addr": "hostname.invalid", "port": 80}},
		{"sockaddr_arg": map[string]any{"family": "AF_INET", "addr": "192.0.2.8", "port": 65536}},
	} {
		fixture := kprobeFixture(tetragonNetworkPolicy, "tcp_v4_connect", argument, nil)
		if _, err := normalizeObservationFixture(t, fixture, 0); !errors.Is(err, ErrUnsupportedEvent) {
			t.Fatal("unproven destination accepted")
		}
	}
}

func TestTetragonObservationSourceIdentityUsesSafeFacts(t *testing.T) {
	fixture := kprobeFixture(tetragonFilePolicy, "vfs_write", map[string]any{"file_arg": map[string]any{"path": "/tmp/file"}}, map[string]any{"long_arg": "5"})
	first, err := normalizeObservationFixture(t, fixture, 0)
	if err != nil {
		t.Fatal(err)
	}
	probe := fixture["process_kprobe"].(map[string]any)
	probe["process"].(map[string]any)["arguments"] = "different private content"
	retry, err := normalizeObservationFixture(t, fixture, time.Minute)
	if err != nil || retry.ID != first.ID {
		t.Fatal("private argv changed the safe source identity")
	}
	probe["return"] = map[string]any{"long_arg": "6"}
	changed, err := normalizeObservationFixture(t, fixture, 0)
	if err != nil || changed.ID == first.ID {
		t.Fatal("different observed bytes shared an identity")
	}
	for _, raw := range []any{"9223372036854775808", 1.5, "not-a-number", true} {
		probe["return"] = map[string]any{"long_arg": raw}
		if _, err := normalizeObservationFixture(t, fixture, 0); !errors.Is(err, ErrUnsupportedEvent) {
			t.Fatal("invalid return accepted")
		}
	}
	probe["return"] = map[string]any{"long_arg": "6", "label": "unexpected"}
	if _, err := normalizeObservationFixture(t, fixture, 0); !errors.Is(err, ErrUnsupportedEvent) {
		t.Fatal("unexpected return label accepted")
	}
}
