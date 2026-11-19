package agent

import (
	"context"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"xe-antishell/internal/detection"
	"xe-antishell/internal/identity"
	"xe-antishell/internal/model"
	"xe-antishell/internal/response"
)

func (s *Service) executeResponses(ctx context.Context, event model.Event, findings []model.Finding, policy *managed.Policy) error {
	if len(findings) == 0 || policy == nil || (policy.Response.Mode != "enforce" && len(policy.Applications) == 0) || !s.config.Response.AllowTerminate {
		return nil
	}
	s.managedRuntime.policyMu.Lock()
	defer s.managedRuntime.policyMu.Unlock()
	for index := range findings {
		finding := &findings[index]
		if finding.DetectionOnly || finding.ResponseDecision != "terminate_pending" {
			continue
		}
		decision, detail := "refused", "live source or approved policy no longer satisfies response requirements"
		effective := s.detectionState.Load().responsePolicyFor(policy, event, *finding)
		eligible := event.Source == "tetragon" && effective != nil && effective.Response.Mode == "enforce" && time.Now().Before(effective.ExpiresAt)
		if eligible {
			// Re-evaluate live capability gates after the observation committed.
			check := []model.Finding{*finding}
			s.applyResponseDecisions(check, effective)
			eligible = check[0].ResponseDecision == "terminate_pending"
		}
		if eligible {
			claimed, err := s.store.ClaimResponse(ctx, finding.ID, event.ID)
			if err != nil {
				return err
			}
			if !claimed {
				decision, detail = "not_repeated", "prior durable response claim exists; original outcome may be unknown after interruption"
			} else {
				actuate, cancel := context.WithDeadline(ctx, effective.ExpiresAt)
				err := response.TerminateInService(actuate, event, time.Now().UTC(), finding.ApplicationService)
				cancel()
				if err != nil {
					detail = err.Error()
				} else {
					decision, detail = "sigterm_sent", "SIGTERM sent through pidfd; process exit is not guaranteed"
				}
			}
		}
		finding.ResponseDecision = decision
		audit := managed.AuditRecord{ID: identity.NewID("audit"), Action: "response.terminate.result", OperationID: finding.ID, OccurredAt: time.Now().UTC(), Result: decision, Details: map[string]string{"event_id": event.ID, "reason": detail}}
		if err := s.store.RecordResponse(ctx, *finding, audit); err != nil {
			return err
		}
	}
	return nil
}

// Called under policyMu so no policy can replace this authorization between
// matching the pending finding and sending the signal.
func (active *detectionState) responsePolicyFor(issued *managed.Policy, event model.Event, finding model.Finding) *managed.Policy {
	if active == nil || active.policy == nil || active.policy.EnrollmentID != issued.EnrollmentID ||
		active.policy.Revision != issued.Revision || finding.PolicyRevision != issued.Revision {
		return nil
	}
	if finding.ApplicationService == "" {
		return active.policy
	}
	app := active.applications[finding.ApplicationService]
	if app == nil || app.definition.PolicyID != finding.ApplicationPolicyID ||
		app.definition.PolicyVersion != finding.ApplicationPolicyVersion || detection.ApplicationServiceCandidate(event) != app.definition.Service {
		return nil
	}
	return app.effective
}
