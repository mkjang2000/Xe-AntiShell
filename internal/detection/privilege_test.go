package detection

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"xe-antishell/internal/lineage"
	"xe-antishell/internal/model"
)

func privilegeEngine(mode string) *Engine {
	return NewWithOptions(Options{WebExecutables: []string{"nginx"}, WebServices: []string{"shop.service"}, Shells: []string{"sh", "bash"}, PrivilegeRules: true, RootExecAlerts: mode})
}
func privID(v uint32) *uint32 { return &v }
func privHost(v bool) *bool   { return &v }
func privSnapshot(uid, euid, suid uint32) *model.CredentialSnapshot {
	return &model.CredentialSnapshot{UID: privID(uid), EUID: privID(euid), SUID: privID(suid), GID: privID(uid), EGID: privID(uid), SGID: privID(uid), FSUID: privID(euid), FSGID: privID(uid),
		Capabilities: &model.CredentialCapabilities{Effective: []string{}, Permitted: []string{}, Inheritable: []string{}}, UserNamespace: &model.UserNamespace{Inum: 4026531837, IsHost: privHost(true)}}
}
func privExec(exe string) model.Event {
	now := time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC)
	return model.Event{ID: "root-exec", BootID: "boot-test", Source: "tetragon", Type: "process.exec", EventTime: now, IngestTime: now,
		Process: model.Process{Key: "child", ExecID: "exec-child", PID: 101, TID: 101, PPID: 1, StartTime: now.Add(-time.Second), Exe: exe, UID: 0, EUID: 0, OriginService: "worker.service", Credentials: privSnapshot(0, 0, 0), LineageConfidence: model.LineageVerified}}
}
func privChange() model.Event {
	event := privExec("/usr/bin/helper")
	event.ID = "credential-event"
	event.Type = "process.credential_change"
	result := int64(0)
	event.Credential = &model.CredentialObservation{Before: privSnapshot(1000, 1000, 1000), After: privSnapshot(1000, 0, 0), TGID: 101, TID: 101, TaskStartTimeNS: 123456789, Evidence: "tetragon_commit_creds_pair", PolicyName: "xeas-credential-change-v1", Function: "commit_creds", ReturnValue: &result, Outcome: "applied"}
	return event
}
func onePrivilege(t *testing.T, event model.Event, rule string, score int) model.Finding {
	t.Helper()
	engine := privilegeEngine("")
	findings := engine.Evaluate(event, lineage.New())
	if len(findings) != 1 || findings[0].RuleID != rule || findings[0].RiskScore != score {
		t.Fatalf("wrong privilege finding: %+v", findings)
	}
	f := findings[0]
	if !f.DetectionOnly || f.RuleVersion != privilegeRuleVersion || len(f.RiskFactors) > 8 || f.RiskScore > 100 {
		t.Fatalf("unsafe finding metadata: %+v", f)
	}
	if privilegeScore(f.RiskFactors) != f.RiskScore {
		t.Fatal("factor total disagrees with score")
	}
	if !reflect.DeepEqual(findings, engine.Evaluate(event, lineage.New())) {
		t.Fatal("retry changed deterministic finding")
	}
	return f
}

func TestPrivilegeRootExecRetentionAndAlertModes(t *testing.T) {
	normal := privExec("/usr/sbin/cron")
	defaultEngine := privilegeEngine("")
	if !defaultEngine.PrivilegeEnabled() || !defaultEngine.IsPrivilegeCandidate(normal) {
		t.Fatal("normal root execution was outside observation scope")
	}
	if f := defaultEngine.Evaluate(normal, lineage.New()); len(f) != 0 {
		t.Fatalf("ordinary root daemon became suspicious: %+v", f)
	}
	all := privilegeEngine("all").Evaluate(normal, lineage.New())
	if len(all) != 1 || all[0].RuleID != "privilege-root-execution" || all[0].RiskScore != 25 || all[0].Severity != "low" || !all[0].DetectionOnly {
		t.Fatalf("wrong all-root profile: %+v", all)
	}
	for _, event := range []model.Event{privExec("/tmp/tool"), privExec("/var/tmp/tool"), privExec("/dev/shm/tool"), privExec("/memfd:owned")} {
		onePrivilege(t, event, "privilege-root-execution", 60)
	}
	unknownShell := privExec("/bin/bash")
	unknownShell.Process.OriginService = ""
	onePrivilege(t, unknownShell, "privilege-root-execution", 45)
	for _, exe := range []string{"/opt/tmp/tool", "/tmp-old/tool", "/tmp/../usr/bin/helper"} {
		event := privExec(exe)
		if f := defaultEngine.Evaluate(event, lineage.New()); len(f) != 0 {
			t.Fatalf("path lookalike caused finding: %s %+v", exe, f)
		}
	}
	for _, field := range []string{"process.euid", "process.exe", "process"} {
		event := privExec("/tmp/tool")
		event.MissingFields = []string{field}
		if defaultEngine.IsPrivilegeCandidate(event) || len(defaultEngine.Evaluate(event, lineage.New())) != 0 {
			t.Fatalf("unavailable %s became root evidence", field)
		}
	}
}

func TestPrivilegeRootExecUsesExplicitContextWithoutTrustingNames(t *testing.T) {
	sudo := privExec("/usr/bin/sudo")
	sudo.Process.ExecPrivileges = &model.ExecPrivileges{SetUID: privID(0)}
	f := onePrivilege(t, sudo, "privilege-root-execution", 45)
	if !strings.Contains(f.Summary, "승인된") || strings.Contains(f.Summary, "악성") {
		t.Fatal("sudo observation was mislabeled as malicious")
	}
	for _, scope := range []string{"non_host", "unknown"} {
		event := privExec("/tmp/root-helper")
		if scope == "non_host" {
			event.Process.Credentials.UserNamespace = &model.UserNamespace{Inum: 99, IsHost: privHost(false)}
		} else {
			event.Process.Credentials.UserNamespace = nil
		}
		finding := onePrivilege(t, event, "privilege-root-execution", 60)
		if strings.Contains(finding.Summary, "초기 user namespace") {
			t.Fatal("container/unknown root was labeled initial namespace root")
		}
	}
	hidden := sudo
	hidden.RedactedFields = []string{"process.exec_privileges"}
	if findings := privilegeEngine("").Evaluate(hidden, lineage.New()); len(findings) != 0 {
		t.Fatal("hidden exec properties contributed risk")
	}
	graph := lineage.New()
	parent := privExec("/bin/bash")
	parent.Process.PID = 100
	parent.Process.ExecID = "parent"
	parent.Process.Key = "parent"
	parent.Process.EUID = 1000
	graph.Observe(&parent)
	child := privExec("/usr/bin/true")
	child.Process.PPID = 100
	child.Process.ParentKey = parent.Process.Key
	graph.Observe(&child)
	findings := privilegeEngine("").Evaluate(child, graph)
	if len(findings) != 1 || findings[0].RiskScore != 45 || findings[0].RiskFactors[1].ID != "nonroot_parent_snapshot" {
		t.Fatalf("lost parent snapshot context: %+v", findings)
	}
	child.MissingFields = []string{"process.parent_identity"}
	if findings := privilegeEngine("").Evaluate(child, graph); len(findings) != 0 {
		t.Fatal("ambiguous parent identity contributed risk")
	}
	// The current PPID is not borrowed when an explicit unknown parent key exists.
	child.MissingFields = nil
	child.Process.ParentKey = "unobserved-old-parent"
	if findings := privilegeEngine("").Evaluate(child, graph); len(findings) != 0 {
		t.Fatal("PID-only parent fallback fabricated privilege gain")
	}
}

func TestPrivilegeCredentialRootGainRestorationAndNamespaceScope(t *testing.T) {
	event := privChange()
	finding := onePrivilege(t, event, "privilege-host-root-gain", 75)
	if finding.Severity != "high" || strings.Contains(finding.Summary, "탈취") {
		t.Fatalf("wrong applied elevation presentation: %+v", finding)
	}
	event.Credential.Before = privSnapshot(0, 1000, 0)
	onePrivilege(t, event, "privilege-root-restored", 40)
	event = privChange()
	event.Credential.Before.SUID = privID(0)
	onePrivilege(t, event, "privilege-root-restored", 40)
	for _, kind := range []string{"non_host", "unknown", "changed"} {
		event := privChange()
		switch kind {
		case "non_host":
			event.Credential.Before.UserNamespace = &model.UserNamespace{Inum: 99, IsHost: privHost(false)}
			event.Credential.After.UserNamespace = event.Credential.Before.UserNamespace.Clone()
		case "unknown":
			event.Credential.Before.UserNamespace.IsHost = nil
			event.Credential.After.UserNamespace.IsHost = nil
		case "changed":
			event.Credential.After.UserNamespace.Inum++
		}
		finding := onePrivilege(t, event, "privilege-root-identity-change", 50)
		if strings.Contains(finding.Summary, "초기 user namespace") || strings.Contains(finding.Summary, "탈취") {
			t.Fatal("namespace ambiguity became host compromise proof")
		}
	}
	event = privChange()
	event.Credential.Before = privSnapshot(0, 0, 0)
	event.Credential.After = privSnapshot(1000, 1000, 1000)
	if f := privilegeEngine("").Evaluate(event, lineage.New()); len(f) != 0 {
		t.Fatalf("root drop alone caused finding: %+v", f)
	}
}

func TestPrivilegeCapabilityAcquisitionDiffersFromPermittedActivation(t *testing.T) {
	event := privChange()
	event.Credential.After = event.Credential.Before.Clone()
	event.Credential.Before.Capabilities.Permitted = []string{"CAP_SYS_ADMIN"}
	event.Credential.After.Capabilities.Permitted = []string{"CAP_SYS_ADMIN"}
	event.Credential.After.Capabilities.Effective = []string{"CAP_SYS_ADMIN"}
	onePrivilege(t, event, "privilege-capability-activated", 25)
	event.Credential.Before.Capabilities.Permitted = []string{}
	onePrivilege(t, event, "privilege-capability-gain", 75)
	event.Credential.After.Capabilities.Effective = []string{}
	onePrivilege(t, event, "privilege-capability-gain", 75)
	event.Credential.Before.Capabilities.Permitted = []string{"CAP_SYS_ADMIN"}
	if findings := privilegeEngine("").Evaluate(event, lineage.New()); len(findings) != 0 {
		t.Fatal("unchanged permitted set produced acquisition")
	}
	event.Credential.Before.Capabilities.Permitted = []string{}
	event.Credential.After.UserNamespace.IsHost = privHost(false)
	event.Credential.Before.UserNamespace.IsHost = privHost(false)
	onePrivilege(t, event, "privilege-capability-gain", 55)
}

func TestPrivilegeCredentialEvidenceCannotInventAppliedTransitions(t *testing.T) {
	changes := map[string]func(*model.Event){
		"wrong source":            func(e *model.Event) { e.Source = "audit" },
		"missing boot":            func(e *model.Event) { e.BootID = "" },
		"cached identity missing": func(e *model.Event) { e.Process.ExecID = "" },
		"different task":          func(e *model.Event) { e.Credential.TGID++ },
		"different thread":        func(e *model.Event) { e.Process.TID++ },
		"unknown return":          func(e *model.Event) { e.Credential.ReturnValue = nil; e.Credential.Outcome = "unknown" },
		"failed":                  func(e *model.Event) { v := int64(-1); e.Credential.ReturnValue = &v; e.Credential.Outcome = "failed" },
		"missing before":          func(e *model.Event) { e.Credential.Before = nil; e.Credential.Outcome = "unknown" },
		"unknown euid":            func(e *model.Event) { e.Credential.Before.EUID = nil; e.Credential.Outcome = "unknown" },
		"wrong policy":            func(e *model.Event) { e.Credential.PolicyName = "unreviewed" },
		"hidden snapshot":         func(e *model.Event) { e.RedactedFields = []string{"credential.before.euid"} },
		"truncated snapshot":      func(e *model.Event) { e.TruncatedFields = []string{"credential"} },
		"hidden current identity": func(e *model.Event) { e.MissingFields = []string{"process.pid"} },
		"invalid caps":            func(e *model.Event) { e.Credential.After.Capabilities.Permitted = []string{"DAC_OVERRIDE"} },
	}
	for name, mutate := range changes {
		t.Run(name, func(t *testing.T) {
			event := privChange()
			mutate(&event)
			if f := privilegeEngine("").Evaluate(event, lineage.New()); len(f) != 0 {
				t.Fatalf("uncertain evidence caused finding: %+v", f)
			}
		})
	}
	unknown := privChange()
	unknown.Credential.ReturnValue = nil
	unknown.Credential.Outcome = "unknown"
	if !privilegeEngine("").IsPrivilegeCandidate(unknown) {
		t.Fatal("unknown operation disappeared from observation scope")
	}
}

func TestPrivilegeProfilePreservesWebRulesAndLegacyDefaults(t *testing.T) {
	event := privExec("/bin/sh")
	event.Process.OriginService = "shop.service"
	engine := privilegeEngine("all")
	findings := engine.Evaluate(event, lineage.New())
	if len(findings) != 1 || findings[0].RuleID != "web-descendant-root-shell" {
		t.Fatalf("existing web finding was duplicated or replaced: %+v", findings)
	}
	for _, event := range []model.Event{privExec("/tmp/command"), privChange()} {
		legacy := NewWithOptions(Options{WebExecutables: []string{"nginx"}, Shells: []string{"sh"}, RootExecAlerts: "all"})
		if legacy.PrivilegeEnabled() || legacy.IsPrivilegeCandidate(event) || len(legacy.Evaluate(event, lineage.New())) != 0 {
			t.Fatal("omitted privilege opt-in altered legacy behavior")
		}
	}
	event = privChange()
	event.Process.Argv = []string{"PRIVATE_CODE"}
	event.Credential.Before.EUID = privID(1000)
	finding := onePrivilege(t, event, "privilege-host-root-gain", 75)
	if strings.Contains(finding.Summary, "PRIVATE") || strings.Contains(finding.Summary, event.Process.Exe) {
		t.Fatal("summary copied command content")
	}
}

func TestPrivilegeRiskBoundAndNoArbitraryProcessRootInference(t *testing.T) {
	event := privChange()
	event.Process.OriginService = "shop.service"
	event.Process.Exe = "/tmp/owned"
	event.Credential.After.Capabilities.Permitted = []string{"CAP_SYS_ADMIN"}
	event.Credential.After.Capabilities.Effective = []string{"CAP_SYS_ADMIN"}
	f := onePrivilege(t, event, "privilege-host-root-gain", 100)
	if f.Severity != "high" || f.Confidence != .95 {
		t.Fatal("wrong bounded evidence metadata")
	}
	// Cached exec identity may still be root, but the direct paired transition
	// is a drop. It must not be reclassified using that cached EUID.
	event = privChange()
	event.Process.EUID = 0
	event.Credential.Before = privSnapshot(0, 0, 0)
	event.Credential.After = privSnapshot(1000, 1000, 1000)
	if len(privilegeEngine("all").Evaluate(event, lineage.New())) != 0 {
		t.Fatal("cached process EUID fabricated a root-gain observation")
	}
	event = privExec("/tmp/tool")
	event.Process.EUID = model.UnknownCredentialID
	if privilegeEngine("all").IsPrivilegeCandidate(event) || len(privilegeEngine("all").Evaluate(event, lineage.New())) != 0 {
		t.Fatal("unknown EUID became root")
	}
}

func TestPrivilegeExecMetadataMustBeAvailableAndReviewed(t *testing.T) {
	for _, properties := range []*model.ExecPrivileges{
		{Reasons: []string{"UNREVIEWED_REASON"}},
		{Reasons: []string{"PRIVILEGES_RAISED_EXEC_FILE_CAP", "PRIVILEGES_RAISED_EXEC_FILE_CAP"}},
		{SetUID: privID(^uint32(0))},
	} {
		event := privExec("/usr/bin/sudo")
		event.Process.ExecPrivileges = properties
		if len(privilegeEngine("").Evaluate(event, lineage.New())) != 0 {
			t.Fatal("unreviewed metadata contributed risk")
		}
	}
	event := privExec("/tmp/helper")
	event.Process.Credentials.UserNamespace.Inum = ^uint64(0)
	findings := privilegeEngine("").Evaluate(event, lineage.New())
	if len(findings) != 1 || strings.Contains(findings[0].Summary, "초기 user namespace") {
		t.Fatal("invalid namespace was treated as host evidence")
	}
}

func TestPrivilegeHiddenWebAttributionDoesNotContributeRisk(t *testing.T) {
	event := privExec("/usr/bin/true")
	event.Process.OriginService = "shop.service"
	event.RedactedFields = []string{"process.origin_service"}
	if len(privilegeEngine("").Evaluate(event, lineage.New())) != 0 {
		t.Fatal("hidden web origin contributed root risk")
	}
	event = privChange()
	event.Process.OriginService = "shop.service"
	event.MissingFields = []string{"process.origin_service"}
	onePrivilege(t, event, "privilege-host-root-gain", 75)
	event.MissingFields = []string{"event_time"}
	if len(privilegeEngine("").Evaluate(event, lineage.New())) != 0 {
		t.Fatal("missing source time became confirmed transition")
	}
}
