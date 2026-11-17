package agent

import (
	"context"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"xe-antishell/internal/identity"
	"xe-antishell/internal/model"
	"xe-antishell/internal/response"
)

func (s *Service) executeResponses(ctx context.Context, event model.Event, findings []model.Finding, policy *managed.Policy) error {
	if policy == nil || policy.Response.Mode != "enforce" || !s.config.Response.AllowTerminate {
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
		active := s.detectionState.Load()
		eligible := event.Source == "tetragon" && active != nil && active.policy != nil && active.policy.Revision == policy.Revision && active.policy.Response.Mode == "enforce" && time.Now().Before(policy.ExpiresAt)
		if eligible {
			// Re-evaluate live capability gates after the observation committed.
			check := []model.Finding{*finding}
			s.applyResponseDecisions(check, policy)
			eligible = check[0].ResponseDecision == "terminate_pending"
		}
		if eligible {
			claimed, err := s.store.ClaimResponse(ctx, finding.ID, event.ID)
			if err != nil {
				return err
			}
			if !claimed {
				decision, detail = "not_repeated", "prior durable response claim exists; original outcome may be unknown after interruption"
			} else if err := response.Terminate(ctx, event, time.Now().UTC()); err != nil {
				detail = err.Error()
			} else {
				decision, detail = "sigterm_sent", "SIGTERM sent through pidfd; process exit is not guaranteed"
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
