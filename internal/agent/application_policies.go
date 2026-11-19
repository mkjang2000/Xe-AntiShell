package agent

import (
	"context"
	"runtime"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"xe-antishell/internal/detection"
	"xe-antishell/internal/model"
	"xe-antishell/internal/response"
)

type systemServiceSource interface {
	SystemService(context.Context, model.Event) (string, error)
}

func (s *Service) supportsApplicationPolicies() bool {
	_, ok := s.processSource.(systemServiceSource)
	return runtime.GOOS == "linux" && ok
}

type applicationDetector struct {
	definition managed.ApplicationPolicy
	effective  *managed.Policy
	engine     *detection.Engine
}

// Match only a fresh, directly attributed event with independently measured
// host system service membership. The inherited web origin remains available
// to the host's observe-only fallback.
func (s *Service) applicationForEvent(ctx context.Context, event model.Event, state *detectionState) *applicationDetector {
	if len(state.applications) == 0 || (event.Source != "tetragon" && event.Source != "audit") {
		return nil
	}
	app := state.applications[detection.ApplicationServiceCandidate(event)]
	if app == nil {
		return nil
	}
	now := time.Now()
	if event.EventTime.After(now) || now.Sub(event.EventTime) > response.MaxEventAge {
		return nil
	}
	source, ok := s.processSource.(systemServiceSource)
	if !ok {
		return nil
	}
	unit, err := source.SystemService(ctx, event)
	if err != nil || unit != app.definition.Service {
		return nil
	}
	return app
}

func (s *Service) evaluateObservation(event model.Event, state *detectionState, app *applicationDetector, at time.Time) []model.Finding {
	if app == nil {
		if !state.enabled {
			return nil
		}
		findings := state.engine.EvaluateAt(event, s.lineage, at)
		s.applyResponseDecisions(findings, state.policy)
		return findings
	}

	var findings []model.Finding
	if app.effective.Detection.Enabled {
		findings = app.engine.EvaluateAt(event, s.lineage, at)
		for i := range findings {
			findings[i].ApplicationPolicyID = app.definition.PolicyID
			findings[i].ApplicationPolicyVersion = app.definition.PolicyVersion
			findings[i].ApplicationService = app.definition.Service
		}
		s.applyResponseDecisions(findings, app.effective)
	}
	if state.privilegeEnabled() {
		global := state.engine.EvaluatePrivilegeAt(event, s.lineage, at)
		s.applyResponseDecisions(global, state.policy)
		findings = append(findings, global...)
	}
	return findings
}

// Latch expiry across clock adjustments until a new policy is accepted.
// In-flight events still recheck the currently published response under policyMu.
func (state *detectionState) withExpiredResponse() *detectionState {
	observe := func(p *managed.Policy) *managed.Policy {
		copy := *p
		copy.Response.Mode, copy.Response.Action = "observe", "none"
		return &copy
	}
	expired := *state
	expired.expired, expired.policy = true, observe(state.policy)
	if len(state.applications) > 0 {
		expired.applications = make(map[string]*applicationDetector, len(state.applications))
		for unit, app := range state.applications {
			copy := *app
			copy.effective = observe(app.effective)
			expired.applications[unit] = &copy
		}
	}
	return &expired
}
