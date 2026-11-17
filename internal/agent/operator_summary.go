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
	if state.policy != nil {
		summary.ExtendedProcessRules = state.policy.Detection.ExtendedProcessRules
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
