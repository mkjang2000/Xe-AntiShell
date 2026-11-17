package agent

import (
	"context"
	"testing"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"xe-antishell/internal/config"
)

func TestSummaryReportsEffectiveDetectionAndResponseMode(t *testing.T) {
	service, store := newTestService(t, config.CollectorDisabled, nil)
	defer store.Close()
	ctx := context.Background()
	summary, err := service.Summary(ctx)
	if err != nil || !summary.DetectionEnabled || summary.ResponseMode != "observe" || summary.ResponseAction != "none" {
		t.Fatalf("local default summary: %+v %v", summary, err)
	}
	policy := managed.DefaultPolicy("agent", "enrollment", 1, time.Now().Add(-time.Minute))
	policy.Response.Mode, policy.Response.Action = "would_block", "terminate"
	service.detectionState.Store(&detectionState{enabled: true, policy: &policy})
	summary, err = service.Summary(ctx)
	if err != nil || summary.ResponseMode != "would_block" || summary.ResponseAction != "terminate" {
		t.Fatalf("simulation summary: %+v %v", summary, err)
	}
	policy.Response.Mode = "enforce"
	summary, err = service.Summary(ctx)
	if err != nil || summary.ResponseMode != "observe" || summary.ResponseAction != "none" {
		t.Fatalf("local opt-out misreported as enforcement: %+v %v", summary, err)
	}
	service.config.Response.AllowTerminate = true
	summary, err = service.Summary(ctx)
	if err != nil || summary.ResponseMode != "enforce" || summary.ResponseAction != "terminate" {
		t.Fatalf("opt-in enforcement summary: %+v %v", summary, err)
	}
	policy.ExpiresAt = time.Now().Add(-time.Second)
	summary, err = service.Summary(ctx)
	if err != nil || summary.ResponseMode != "observe" || summary.ResponseAction != "none" {
		t.Fatalf("expired policy misreported as enforcement: %+v %v", summary, err)
	}
	service.detectionState.Store(&detectionState{enabled: false})
	summary, err = service.Summary(ctx)
	if err != nil || summary.DetectionEnabled {
		t.Fatalf("disabled detection summary: %+v %v", summary, err)
	}
}
