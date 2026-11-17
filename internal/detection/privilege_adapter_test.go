package detection

import (
	"encoding/json"
	"slices"
	"testing"
	"time"

	"xe-antishell/internal/collector"
	"xe-antishell/internal/lineage"
	"xe-antishell/internal/model"
)

// Exercise the actual source adapter, including its scope advisory marker.
// Process execution credentials intentionally differ from the same-hook Before.
func normalizePrivilegePair(t *testing.T, before, after map[string]any) model.Event {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"time": "2026-11-18T01:00:01Z",
		"process_kprobe": map[string]any{
			"process":     map[string]any{"pid": 42, "tid": 43, "exec_id": "source-generation", "binary": "/usr/bin/helper", "start_time": "2026-11-18T01:00:00Z", "uid": 0},
			"policy_name": model.CredentialPolicyName, "function_name": "commit_creds", "action": "KPROBE_ACTION_POST",
			"args": []any{map[string]any{"label": "after", "process_credentials_arg": after}},
			"data": []any{
				map[string]any{"label": "before", "process_credentials_arg": before},
				map[string]any{"label": "tid", "int_arg": 43},
				map[string]any{"label": "task_start", "size_arg": "9007199254740993"},
				map[string]any{"label": "tgid", "int_arg": 42},
			},
			"return": map[string]any{"int_arg": 0},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	event, err := collector.NormalizeTetragonJSON(raw, time.Date(2026, 11, 18, 1, 0, 2, 0, time.UTC), collector.Metadata{HostID: "host", BootID: "boot"})
	if err != nil {
		t.Fatal(err)
	}
	return event
}

func rawPrivilegeCredential(euid uint32, scope string) map[string]any {
	ns := map[string]any{"inum": 4026531837}
	level := 0
	if scope == "host" {
		ns["is_host"] = true
	}
	if scope == "non_host" {
		ns["is_host"] = false
		ns["inum"] = 4026532444
		level = 1
	}
	return map[string]any{"uid": 1000, "euid": euid, "gid": 1000, "egid": 1000, "suid": 1000, "sgid": 1000, "fsuid": euid, "fsgid": 1000,
		"caps": map[string]any{}, "user_ns": map[string]any{"level": level, "ns": ns}}
}

func TestTetragonCredentialScopeAdvisoryPreservesGenericDetection(t *testing.T) {
	for _, test := range []struct {
		name, beforeScope, afterScope, rule string
		score                               int
		capability, activation              bool
	}{
		{name: "known initial namespace", beforeScope: "host", afterScope: "host", rule: "privilege-host-root-gain", score: 75},
		{name: "unknown scope", beforeScope: "unknown", afterScope: "unknown", rule: "privilege-root-identity-change", score: 50},
		{name: "partly unknown scope", beforeScope: "host", afterScope: "unknown", rule: "privilege-root-identity-change", score: 50},
		{name: "known non host", beforeScope: "non_host", afterScope: "non_host", rule: "privilege-root-identity-change", score: 50},
		{name: "unknown scope capability acquisition", beforeScope: "unknown", afterScope: "unknown", rule: "privilege-capability-gain", score: 55, capability: true},
		{name: "unknown scope existing permitted activation", beforeScope: "unknown", afterScope: "unknown", rule: "privilege-capability-activated", score: 25, activation: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			before, after := rawPrivilegeCredential(1000, test.beforeScope), rawPrivilegeCredential(0, test.afterScope)
			if test.capability || test.activation {
				after["euid"], after["fsuid"] = 1000, 1000
				after["caps"] = map[string]any{"effective": []string{"CAP_SYS_ADMIN"}, "permitted": []string{"CAP_SYS_ADMIN"}}
				if test.activation {
					before["caps"] = map[string]any{"permitted": []string{"CAP_SYS_ADMIN"}}
				}
			}
			event := normalizePrivilegePair(t, before, after)
			unknown := test.beforeScope == "unknown" || test.afterScope == "unknown"
			if event.Credential.Outcome != "applied" || slices.Contains(event.MissingFields, "credential.user_namespace_scope") != unknown {
				t.Fatalf("adapter proof/marker changed: %+v", event)
			}
			finding := onePrivilege(t, event, test.rule, test.score)
			if unknown && finding.RuleID == "privilege-host-root-gain" {
				t.Fatal("scope uncertainty became a host root claim")
			}
		})
	}
}

func TestTetragonCredentialScopeAdvisoryNeverOverridesLostProof(t *testing.T) {
	event := normalizePrivilegePair(t, rawPrivilegeCredential(1000, "unknown"), rawPrivilegeCredential(0, "unknown"))
	for _, test := range []struct{ name, kind, path string }{
		{"missing before euid", "missing", "credential.before.euid"},
		{"missing pair", "missing", "credential"},
		{"missing snapshot", "missing", "credential.before"},
		{"redacted capabilities", "redacted", "credential.after.capabilities"},
		{"truncated return", "truncated", "credential.return_value"},
		{"advisory prefix lookalike", "missing", "credential.user_namespace_scope.extra"},
		{"redacted advisory", "redacted", "credential.user_namespace_scope"},
		{"truncated advisory", "truncated", "credential.user_namespace_scope"},
	} {
		t.Run(test.name, func(t *testing.T) {
			broken := event
			switch test.kind {
			case "missing":
				broken.MissingFields = append(slices.Clone(event.MissingFields), test.path)
			case "redacted":
				broken.RedactedFields = append(slices.Clone(event.RedactedFields), test.path)
			case "truncated":
				broken.TruncatedFields = append(slices.Clone(event.TruncatedFields), test.path)
			}
			if findings := privilegeEngine("").Evaluate(broken, lineage.New()); len(findings) != 0 {
				t.Fatalf("scope advisory overrode missing proof: %+v", findings)
			}
		})
	}
	known := normalizePrivilegePair(t, rawPrivilegeCredential(1000, "host"), rawPrivilegeCredential(0, "host"))
	known.MissingFields = append(known.MissingFields, "credential.user_namespace_scope")
	if findings := privilegeEngine("").Evaluate(known, lineage.New()); len(findings) != 0 {
		t.Fatalf("contradictory unknown marker became strong host proof: %+v", findings)
	}
}
