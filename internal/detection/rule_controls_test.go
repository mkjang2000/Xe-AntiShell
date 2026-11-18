package detection

import (
	"testing"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"xe-antishell/internal/lineage"
	"xe-antishell/internal/model"
)

func TestServiceRuleAttributionProfilesAndExpiry(t *testing.T) {
	at := time.Now().UTC()
	end := at.Add(time.Hour)
	shell := managed.ServiceRuleControl{Service: "shop.service", RuleID: ruleWebDescendantShell, Mode: "suppress_until", Reason: "maintenance", ExpiresAt: &end}
	opts := Options{WebServices: []string{"shop.service", "other.service"}, WebExecutables: []string{"nginx"}, Shells: []string{"sh"}, ServiceRuleControls: []managed.ServiceRuleControl{shell}}
	engine := NewWithOptions(opts)
	graph := lineage.New()
	e := extendedEvent("/bin/sh")
	e.EventTime = end.Add(time.Hour)
	check := func(e model.Event, when time.Time, expect string) {
		t.Helper()
		f := engine.EvaluateAt(e, graph, when)
		if expect == "" && len(f) != 0 || expect != "" && (len(f) != 1 || f[0].RuleID != expect) {
			t.Fatalf("want %q from service %s at %v; got %+v", expect, e.Process.OriginService, when, f)
		}
	}
	check(e, end.Add(-time.Nanosecond), "")
	check(e, end, ruleWebDescendantShell)
	for _, s := range []string{"Shop.service", "other.service"} {
		x := e
		x.Process.OriginService = s
		check(x, at, ruleWebDescendantShell)
	}
	x := e
	x.TruncatedFields = []string{"process.origin_service"}
	check(x, at, ruleWebDescendantShell)
	parent := model.Event{Type: "process.exec", EventTime: at, BootID: "boot", Process: model.Process{PID: 100, Key: "parent", Exe: "/usr/sbin/nginx"}}
	graph.Observe(&parent)
	x = e
	x.Process.OriginService = ""
	x.Process.ParentKey = ""
	check(x, at, ruleWebDescendantShell)
	x = e
	x.Process.Exe = "/usr/bin/curl"
	opts.ServiceRuleControls = []managed.ServiceRuleControl{{Service: "shop.service", RuleID: ruleWebDescendantDownloadTool, Mode: "enabled"}}
	engine = NewWithOptions(opts)
	check(x, at, "")
	opts.ExtendedProcessRules = true
	opts.ServiceRuleControls = []managed.ServiceRuleControl{{Service: "shop.service", RuleID: ruleWebDescendantTemporaryExecutable, Mode: "disabled"}}
	engine = NewWithOptions(opts)
	x.Process.Exe = "/tmp/curl"
	check(x, at, ruleWebDescendantDownloadTool)
	// An exception to a web rule leaves independently enabled global rules eligible.
	opts.PrivilegeRules = true
	opts.RootExecAlerts = "all"
	opts.ServiceRuleControls = []managed.ServiceRuleControl{{Service: "shop.service", RuleID: ruleWebDescendantRootShell, Mode: "disabled"}}
	engine = NewWithOptions(opts)
	x = e
	x.Process.EUID = 0
	check(x, at, rulePrivilegeRootExecution)
}

func TestSharedRuleIDsMatchCompleteCatalog(t *testing.T) {
	known := map[string]bool{}
	for _, id := range managed.BuiltinRuleIDs() {
		known[id] = true
	}
	for _, r := range RuleDefinitions() {
		if !known[r.ID] {
			t.Fatalf("unknown or duplicated catalog ID %s", r.ID)
		}
		delete(known, r.ID)
	}
	if len(known) != 0 {
		t.Fatalf("unused wire rule IDs %v", known)
	}
}
