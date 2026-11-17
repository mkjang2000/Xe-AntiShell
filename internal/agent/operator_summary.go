package agent

import (
	"context"
	"time"

	"xe-antishell/internal/model"
)

func (s *Service) Summary(ctx context.Context) (model.OperatorSummary, error) {
	now := time.Now().UTC()
	summary, err := s.store.OperatorSummary(ctx, now)
	if err != nil {
		return summary, err
	}
	summary.ResponseMode, summary.ResponseAction = "observe", "none"
	state := s.detectionState.Load()
	if state == nil {
		return summary, nil
	}
	summary.DetectionEnabled = state.enabled
	summary.ExtendedProcessRules = s.config.Detection.ExtendedProcessRules
	summary.PrivilegeRules = s.config.Detection.PrivilegeRules
	summary.RootExecAlerts = s.config.Detection.RootExecAlerts
	if state.policy != nil {
		summary.ExtendedProcessRules = state.policy.Detection.ExtendedProcessRules
		summary.PrivilegeRules = state.policy.Detection.PrivilegeRules
		summary.RootExecAlerts = state.policy.Detection.RootExecAlerts
	}
	if !summary.PrivilegeRules {
		summary.RootExecAlerts = ""
	} else if summary.RootExecAlerts == "" {
		summary.RootExecAlerts = "suspicious"
	}
	if summary.ExtendedProcessRules {
		// Every finding from this staged profile is detection-only, including
		// the legacy shell categories. Report the effective behavior.
		return summary, nil
	}
	if state.policy == nil || !now.Before(state.policy.ExpiresAt) {
		return summary, nil
	}
	response := state.policy.Response
	if response.Mode == "enforce" && !s.config.Response.AllowTerminate {
		return summary, nil
	}
	summary.ResponseMode, summary.ResponseAction = response.Mode, response.Action
	return summary, nil
}
