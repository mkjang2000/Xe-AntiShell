package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"xe-antishell/internal/config"
)

func TestPrivilegeSummaryUsesEffectivePolicyWithoutDisablingWebResponse(t *testing.T) {
	service, store := newTestService(t, config.CollectorDisabled, func(cfg *config.Config) { cfg.Detection.PrivilegeRules = true })
	defer store.Close()
	ctx := context.Background()
	summary, err := service.Summary(ctx)
	if err != nil || !summary.PrivilegeRules || summary.RootExecAlerts != "suspicious" {
		t.Fatalf("local effective privilege config: %+v %v", summary, err)
	}
	policy := managed.DefaultPolicy("agent", "enrollment", 1, time.Now().Add(-time.Minute))
	policy.Response.Mode, policy.Response.Action = "would_block", "terminate"
	service.detectionState.Store(&detectionState{enabled: true, policy: &policy})
	summary, err = service.Summary(ctx)
	if err != nil || summary.PrivilegeRules || summary.RootExecAlerts != "" || summary.ResponseMode != "would_block" {
		t.Fatalf("signed policy must override local opt-in: %+v %v", summary, err)
	}
	policy.Detection.PrivilegeRules, policy.Detection.RootExecAlerts = true, "all"
	for _, mode := range []string{"would_block", "enforce"} {
		policy.Response.Mode = mode
		service.config.Response.AllowTerminate = true
		summary, err = service.Summary(ctx)
		if err != nil || !summary.PrivilegeRules || summary.RootExecAlerts != "all" || summary.ResponseMode != mode || summary.ResponseAction != "terminate" {
			t.Fatalf("privilege-only must preserve web response: %+v %v", summary, err)
		}
	}
	policy.Detection.ExtendedProcessRules = true
	summary, err = service.Summary(ctx)
	if err != nil || !summary.PrivilegeRules || summary.ResponseMode != "observe" || summary.ResponseAction != "none" {
		t.Fatalf("extended profile retains existing observe-only semantics: %+v %v", summary, err)
	}
	policy.Detection.PrivilegeRules, policy.Detection.RootExecAlerts = false, ""
	summary, err = service.Summary(ctx)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(summary)
	if err != nil || strings.Contains(string(data), "privilege_rules") || strings.Contains(string(data), "root_exec_alerts") {
		t.Fatalf("disabled optional fields leaked: %s %v", data, err)
	}
}
