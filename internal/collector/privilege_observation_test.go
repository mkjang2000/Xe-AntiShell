package collector

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"xe-antishell/internal/model"
)

func credentialSnapshotFixture(euid uint32) map[string]any {
	return map[string]any{"uid": 1000, "euid": euid, "gid": 1000, "egid": 1000,
		"suid": 1000, "sgid": 1000, "fsuid": euid, "fsgid": 1000, "caps": map[string]any{},
		"user_ns": map[string]any{"level": 0, "ns": map[string]any{"inum": 4026531837, "is_host": true}}}
}

func credentialFixture() map[string]any {
	fixture := kprobeFixture(tetragonCredentialPolicy, "commit_creds",
		map[string]any{"process_credentials_arg": credentialSnapshotFixture(0), "label": "after"}, map[string]any{"int_arg": 0})
	probe := fixture["process_kprobe"].(map[string]any)
	probe["data"] = []any{
		map[string]any{"process_credentials_arg": credentialSnapshotFixture(1000), "label": "before"},
		map[string]any{"int_arg": 43, "label": "tid"},
		map[string]any{"size_arg": "100000000001", "label": "task_start"},
		map[string]any{"int_arg": 42, "label": "tgid"},
	}
	probe["process"].(map[string]any)["tid"] = 43
	return fixture
}

func credentialProbe(fixture map[string]any) map[string]any {
	return fixture["process_kprobe"].(map[string]any)
}

func credentialBefore(probe map[string]any) map[string]any {
	return probe["data"].([]any)[0].(map[string]any)["process_credentials_arg"].(map[string]any)
}

func credentialAfter(probe map[string]any) map[string]any {
	return probe["args"].([]any)[0].(map[string]any)["process_credentials_arg"].(map[string]any)
}

func TestTetragonCredentialUsesSameHookBeforeAndReturn(t *testing.T) {
	fixture := credentialFixture()
	probe := credentialProbe(fixture)
	// The exec snapshot is deliberately stale and different from current_task.
	probe["process"].(map[string]any)["process_credentials"] = credentialSnapshotFixture(0)
	event, err := normalizeObservationFixture(t, fixture, 0)
	if err != nil {
		t.Fatal(err)
	}
	observation := event.Credential
	if event.Type != "process.credential_change" || observation == nil || observation.Outcome != "applied" || observation.ReturnValue == nil || *observation.ReturnValue != 0 ||
		observation.Evidence != model.CredentialEvidence || observation.PolicyName != tetragonCredentialPolicy || observation.Function != "commit_creds" ||
		observation.TGID != 42 || observation.TID != 43 || observation.TaskStartTimeNS != 100000000001 {
		t.Fatalf("wrong credential observation: %+v", observation)
	}
	if observation.Before == nil || observation.Before.EUID == nil || *observation.Before.EUID != 1000 || observation.After == nil || observation.After.EUID == nil || *observation.After.EUID != 0 {
		t.Fatal("cached process snapshot was used in place of same-hook before/after")
	}
	if event.Process.Credentials == nil || *event.Process.Credentials.EUID != 0 || event.Process.EUID != 0 || event.Process.TID != 43 {
		t.Fatal("separate execution context was rewritten by credential Before")
	}
	if event.Process.Key == "" || event.Process.ParentKey == "" || observation.Before.UserNamespace.Scope() != "host" || event.Completeness != model.CompletenessComplete {
		t.Fatal("same-hook identity/namespace context was lost")
	}
	encoded, _ := json.Marshal(event)
	if strings.Contains(string(encoded), observationPrivateFixture) || len(event.RawJSON) != 0 || len(event.Process.Argv) != 0 || len(event.Ancestors[0].Argv) != 0 {
		t.Fatal("credential event retained raw arguments, environment or code")
	}
}

func TestTetragonCredentialRequiresExactTupleAndTaskIdentity(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(map[string]any)
	}{
		{"other policy", func(p map[string]any) { p["policy_name"] = "process-creds-changed" }},
		{"other hook", func(p map[string]any) { p["function_name"] = "prepare_creds" }},
		{"subsystem", func(p map[string]any) { p["subsys"] = "sched" }},
		{"enforcement", func(p map[string]any) { p["action"] = "KPROBE_ACTION_SIGKILL" }},
		{"return enforcement", func(p map[string]any) { p["return_action"] = "KPROBE_ACTION_OVERRIDE" }},
		{"missing exec id", func(p map[string]any) { delete(p["process"].(map[string]any), "exec_id") }},
		{"missing start", func(p map[string]any) { delete(p["process"].(map[string]any), "start_time") }},
		{"relative binary", func(p map[string]any) { p["process"].(map[string]any)["binary"] = "python" }},
		{"fork parent PID", func(p map[string]any) { p["process"].(map[string]any)["pid"] = 41 }},
		{"wrong source TID", func(p map[string]any) { p["process"].(map[string]any)["tid"] = 44 }},
		{"wrong parent", func(p map[string]any) { p["parent"].(map[string]any)["exec_id"] = "other" }},
		{"missing data", func(p map[string]any) { p["data"] = nil }},
		{"extra data", func(p map[string]any) {
			p["data"] = append(p["data"].([]any), map[string]any{"int_arg": 42, "label": "extra"})
		}},
		{"missing before label", func(p map[string]any) { delete(p["data"].([]any)[0].(map[string]any), "label") }},
		{"wrong after label", func(p map[string]any) { p["args"].([]any)[0].(map[string]any)["label"] = "before" }},
		{"extra argument", func(p map[string]any) {
			p["args"].([]any)[0].(map[string]any)["string_arg"] = observationPrivateFixture
		}},
		{"wrong data order", func(p map[string]any) { d := p["data"].([]any); d[1], d[3] = d[3], d[1] }},
		{"missing tid", func(p map[string]any) { p["data"].([]any)[1].(map[string]any)["int_arg"] = 0 }},
		{"negative task lifetime", func(p map[string]any) { p["data"].([]any)[2].(map[string]any)["size_arg"] = "-1" }},
		{"fractional task lifetime", func(p map[string]any) { p["data"].([]any)[2].(map[string]any)["size_arg"] = "1.5" }},
		{"task lifetime overflow", func(p map[string]any) { p["data"].([]any)[2].(map[string]any)["size_arg"] = "18446744073709551616" }},
		{"pid overflow", func(p map[string]any) { p["data"].([]any)[3].(map[string]any)["int_arg"] = "2147483648" }},
		{"positive result", func(p map[string]any) { p["return"] = map[string]any{"int_arg": 1} }},
		{"wrong return type", func(p map[string]any) { p["return"] = map[string]any{"long_arg": 0} }},
		{"malformed IDs", func(p map[string]any) { credentialBefore(p)["euid"] = "zero" }},
		{"unknown credential field", func(p map[string]any) { credentialBefore(p)["cached_old_euid"] = 1000 }},
		{"invalid IDs", func(p map[string]any) { credentialBefore(p)["uid"] = uint32(4294967295) }},
		{"invalid namespace", func(p map[string]any) {
			credentialBefore(p)["user_ns"].(map[string]any)["ns"].(map[string]any)["inum"] = uint64(4294967296)
		}},
		{"invalid level", func(p map[string]any) { credentialBefore(p)["user_ns"].(map[string]any)["level"] = -1 }},
		{"contradictory namespace level", func(p map[string]any) { credentialBefore(p)["user_ns"].(map[string]any)["level"] = 1 }},
		{"unknown capability", func(p map[string]any) {
			credentialAfter(p)["caps"].(map[string]any)["effective"] = []string{"CAP_SECRET_NEW"}
		}},
		{"aliased duplicate", func(p map[string]any) {
			credentialAfter(p)["caps"].(map[string]any)["effective"] = []string{"DAC_OVERRIDE", "CAP_DAC_OVERRIDE"}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := credentialFixture()
			test.change(credentialProbe(fixture))
			if _, err := normalizeObservationFixture(t, fixture, 0); !errors.Is(err, ErrUnsupportedEvent) {
				t.Fatalf("unsupported credential tuple error=%v", err)
			}
		})
	}
	for _, kind := range []string{"process_exec", "process_exit", "process_tracepoint"} {
		fixture := credentialFixture()
		fixture[kind] = map[string]any{}
		if _, err := normalizeObservationFixture(t, fixture, 0); !errors.Is(err, ErrUnsupportedEvent) {
			t.Fatalf("conflicting %s accepted: %v", kind, err)
		}
	}
}

func TestTetragonCredentialPartialEvidenceStaysUnknown(t *testing.T) {
	for _, test := range []struct {
		name    string
		change  func(map[string]any)
		outcome string
		partial bool
	}{
		{"missing return", func(p map[string]any) { delete(p, "return") }, "unknown", true},
		{"missing real UID", func(p map[string]any) { delete(credentialBefore(p), "uid") }, "unknown", true},
		{"missing effective UID", func(p map[string]any) { delete(credentialAfter(p), "euid") }, "unknown", true},
		{"missing caps", func(p map[string]any) { delete(credentialAfter(p), "caps") }, "unknown", true},
		{"missing namespace", func(p map[string]any) { delete(credentialBefore(p), "user_ns") }, "unknown", true},
		{"unknown namespace scope", func(p map[string]any) {
			delete(credentialBefore(p)["user_ns"].(map[string]any)["ns"].(map[string]any), "is_host")
		}, "applied", true},
		{"null before", func(p map[string]any) { p["data"].([]any)[0].(map[string]any)["process_credentials_arg"] = nil }, "unknown", true},
		{"failed call", func(p map[string]any) { p["return"] = map[string]any{"int_arg": -1, "label": "result"} }, "failed", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := credentialFixture()
			test.change(credentialProbe(fixture))
			event, err := normalizeObservationFixture(t, fixture, 0)
			if err != nil || event.Credential == nil || event.Credential.Outcome != test.outcome {
				t.Fatalf("partial outcome=%+v err=%v", event.Credential, err)
			}
			if test.partial != (event.Completeness == model.CompletenessPartial) {
				t.Fatalf("partial status incorrect: %s", event.Completeness)
			}
			if err := event.Credential.Validate(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestTetragonCredentialCapabilityChangesCanonicalized(t *testing.T) {
	fixture := credentialFixture()
	probe := credentialProbe(fixture)
	credentialAfter(probe)["euid"], credentialAfter(probe)["fsuid"] = 1000, 1000
	credentialAfter(probe)["caps"] = map[string]any{"effective": []string{"CAP_SETUID", "DAC_OVERRIDE"}, "permitted": []string{"CAP_SETUID", "CAP_DAC_OVERRIDE"}}
	event, err := normalizeObservationFixture(t, fixture, 0)
	if err != nil || event.Credential.Outcome != "applied" {
		t.Fatalf("capability-only event lost: %v", err)
	}
	if actual := strings.Join(event.Credential.After.Capabilities.Effective, ","); actual != "CAP_DAC_OVERRIDE,CAP_SETUID" {
		t.Fatalf("capability spelling/order not canonical: %s", actual)
	}
	// Aliases and ordering must not alter stable identity on retry.
	credentialAfter(probe)["caps"] = map[string]any{"effective": []string{"CAP_DAC_OVERRIDE", "CAP_SETUID"}, "permitted": []string{"CAP_DAC_OVERRIDE", "CAP_SETUID"}}
	retry, err := normalizeObservationFixture(t, fixture, time.Hour)
	if err != nil || retry.ID != event.ID {
		t.Fatal("equivalent capability sets changed source identity")
	}
}

func TestTetragonCredentialIdentityPreservesRapidRoundTrips(t *testing.T) {
	fixture := credentialFixture()
	first, err := normalizeObservationFixture(t, fixture, 0)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := normalizeObservationFixture(t, fixture, time.Hour)
	if err != nil || first.ID != retry.ID {
		t.Fatal("duplicate delivery lost stable source identity")
	}
	fixture["time"] = "2026-11-17T00:00:01.000000001Z"
	later, err := normalizeObservationFixture(t, fixture, 0)
	if err != nil || later.ID == first.ID {
		t.Fatal("later repeated transition collapsed into previous event")
	}
	probe := credentialProbe(fixture)
	probe["data"].([]any)[0].(map[string]any)["process_credentials_arg"] = credentialSnapshotFixture(0)
	probe["args"].([]any)[0].(map[string]any)["process_credentials_arg"] = credentialSnapshotFixture(1000)
	reversed, err := normalizeObservationFixture(t, fixture, 0)
	if err != nil || reversed.ID == later.ID {
		t.Fatal("same-timestamp reverse transition collapsed into previous event")
	}
	probe["data"].([]any)[2].(map[string]any)["size_arg"] = "9007199254740993"
	exact, err := normalizeObservationFixture(t, fixture, 0)
	if err != nil || exact.Credential.TaskStartTimeNS != 9007199254740993 {
		t.Fatal("uint64 task identity lost precision")
	}
}

func TestTetragonCredentialUnchangedIsSkippedBeforeQueue(t *testing.T) {
	fixture := credentialFixture()
	credentialProbe(fixture)["args"].([]any)[0].(map[string]any)["process_credentials_arg"] = credentialSnapshotFixture(1000)
	raw, _ := json.Marshal(fixture)
	collector := NewTetragonJSON(CommandSpec{Path: "not-executed"}, Metadata{BootID: "boot"})
	called := false
	err := collector.consume(context.Background(), strings.NewReader(string(raw)+"\n"), SinkFunc(func(context.Context, model.Event) error { called = true; return nil }))
	health := collector.Health()
	if err != nil || called || health.EventsReceived != 1 || health.EventsEmitted != 0 || health.ParseErrors != 0 || health.EventsDropped != 1 {
		t.Fatalf("intentional skip reached queue or was a parse failure: %+v err=%v", health, err)
	}
}

func TestTetragonCredentialNamespaceScopeIsExplicit(t *testing.T) {
	for _, test := range []struct {
		name  string
		value any
		scope string
	}{
		{"host", true, "host"}, {"non host", false, "non_host"}, {"omitted", nil, "unknown"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := credentialFixture()
			ns := credentialAfter(credentialProbe(fixture))["user_ns"].(map[string]any)["ns"].(map[string]any)
			if test.value == nil {
				delete(ns, "is_host")
			} else {
				ns["is_host"] = test.value
				if test.value == false {
					credentialAfter(credentialProbe(fixture))["user_ns"].(map[string]any)["level"] = 1
				}
			}
			event, err := normalizeObservationFixture(t, fixture, 0)
			if err != nil || event.Credential.After.UserNamespace.Scope() != test.scope {
				t.Fatalf("scope mismatch err=%v", err)
			}
		})
	}
}
