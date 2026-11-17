package agent

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"xe-antishell/internal/detection"
	"xe-antishell/internal/model"
	"xe-antishell/internal/response"
	"xe-antishell/internal/storage"
)

// A snapshot is immutable after publication, so an event uses the same policy
// for origin filtering, rule evaluation, and response decisions.
type detectionState struct {
	engine  *detection.Engine
	enabled bool
	policy  *managed.Policy
}

func (s *Service) currentMonitoring() managed.MonitoringPolicy {
	if state := s.detectionState.Load(); state != nil && state.policy != nil {
		return state.policy.Monitoring
	}
	return managed.MonitoringPolicy{Enabled: true, SampleIntervalSeconds: 10, ProcessLimit: 200}
}

func (s *Service) applyManagedPolicy(ctx context.Context, signed managed.SignedPolicy, enrollment storage.ManagedState, now time.Time, restoring bool) error {
	runtime := s.managedRuntime
	runtime.policyMu.Lock()
	defer runtime.policyMu.Unlock()
	key, err := managed.DecodePublicKey(enrollment.PolicyPublicKey)
	if err != nil {
		return errors.New("invalid pinned policy key")
	}
	var minimum uint64
	if previous, err := s.store.Policy(ctx); err == nil {
		minimum = previous.Policy.Revision
	} else if !errors.Is(err, storage.ErrNotFound) {
		return errors.New("read approved policy failed")
	}
	verificationTime := now
	if restoring && !now.Before(signed.Policy.ExpiresAt) {
		// Authenticate a previously committed policy before retaining its
		// detection settings. Expiry always disables response decisions.
		verificationTime = signed.Policy.ExpiresAt.Add(-time.Nanosecond)
	}
	policy, err := managed.VerifyPolicy(signed, map[string]ed25519.PublicKey{enrollment.PolicyKeyID: key}, enrollment.AgentID, enrollment.EnrollmentID, minimum, verificationTime)
	if err != nil {
		return err
	}
	runtime.mu.Lock()
	runtime.status.Policy.DesiredRevision = policy.Revision
	runtime.mu.Unlock()
	if policy.Response.Mode == "enforce" {
		if !s.config.Response.AllowTerminate {
			return errors.New("host-local termination opt-in is disabled")
		}
		if response.Capability(true).State != model.CapabilitySupported {
			return errors.New("pidfd termination is unsupported on this host")
		}
	}
	if err := s.validatePolicyCoverage(policy); err != nil {
		return err
	}
	if err := s.store.SavePolicy(ctx, signed); err != nil {
		return err
	}
	result, policyError := "applied", ""
	if !now.Before(policy.ExpiresAt) {
		policy.Response.Mode, policy.Response.Action = "observe", "none"
		result, policyError = "stale", "approved policy expired; detection continues with response disabled"
	}
	s.detectionState.Store(&detectionState{
		engine: detection.NewWithOptions(detection.Options{
			WebExecutables:       policy.Detection.WebExecutables,
			WebServices:          policy.Detection.WebServices,
			Shells:               policy.Detection.Shells,
			AllowedPairs:         policy.Detection.AllowedPairs,
			ExtendedProcessRules: policy.Detection.ExtendedProcessRules,
			PrivilegeRules:       policy.Detection.PrivilegeRules,
			RootExecAlerts:       policy.Detection.RootExecAlerts,
		}),
		enabled: policy.Detection.Enabled, policy: &policy,
	})
	runtime.mu.Lock()
	runtime.status.Policy = managed.PolicyStatus{DesiredRevision: policy.Revision, ActiveRevision: policy.Revision, Result: result, Error: policyError, AppliedAt: &now}
	runtime.mu.Unlock()
	return nil
}

func (s *Service) validatePolicyCoverage(policy managed.Policy) error {
	if policy.Detection.PrivilegeRules {
		if !privilegeArgumentsUsable(s.config.Collector.Tetragon.Args) {
			return errors.New("privilege observation cannot use source-side event filters")
		}
		if s.currentCollectorName() == "audit-dispatcher" && len(s.config.Collector.Audit.IncludeExecutables) != 0 {
			return errors.New("global root observation requires an unfiltered audit input")
		}
	}

	if policy.Detection.ExtendedProcessRules && (len(s.config.Collector.Audit.IncludeExecutables) != 0 || len(s.config.Collector.Tetragon.IncludeExecutables) != 0) {
		return errors.New("extended process rules require empty audit and Tetragon executable filters")
	}
	if !policy.Detection.Enabled {
		return nil
	}
	// Collector command arguments and input scopes remain local. Do not claim
	// that a remotely added shell is covered when the collector filters it out.
	for _, allowed := range [][]string{s.config.Collector.Audit.IncludeExecutables, s.config.Collector.Tetragon.IncludeExecutables} {
		if len(allowed) == 0 {
			continue
		}
		for _, shell := range policy.Detection.Shells {
			found := false
			for _, executable := range allowed {
				found = found || strings.EqualFold(shell, executable)
			}
			if !found {
				return fmt.Errorf("shell %q is outside a locally configured collector input scope", shell)
			}
		}
	}
	return nil
}

func (s *Service) refreshPolicyExpiry(now time.Time) {
	runtime := s.managedRuntime
	runtime.policyMu.Lock()
	defer runtime.policyMu.Unlock()
	state := s.detectionState.Load()
	if state == nil || state.policy == nil || now.Before(state.policy.ExpiresAt) {
		return
	}
	if state.policy.Response.Mode != "observe" || state.policy.Response.Action != "none" {
		policy := *state.policy
		policy.Response.Mode, policy.Response.Action = "observe", "none"
		s.detectionState.Store(&detectionState{engine: state.engine, enabled: state.enabled, policy: &policy})
	}
	runtime.mu.Lock()
	runtime.status.Policy.Result = "stale"
	runtime.status.Policy.Error = "approved policy expired; detection continues with response disabled"
	runtime.mu.Unlock()
}

func (s *Service) applyResponseDecisions(findings []model.Finding, policy *managed.Policy) {
	var report model.CapabilityReport
	if policy != nil && (policy.Response.Mode == "would_block" || policy.Response.Mode == "enforce") {
		_, report = s.runtimeSnapshot()
	}
	for index := range findings {
		finding := &findings[index]
		if len(finding.RiskFactors) == 0 {
			switch finding.Severity {
			case "critical":
				finding.RiskScore = 95
			case "high":
				finding.RiskScore = 85
			case "medium":
				finding.RiskScore = 60
			default:
				finding.RiskScore = 30
			}
		}
		finding.ResponseDecision = "observe"
		if policy != nil {
			finding.PolicyRevision = policy.Revision
		}
		// Extended rules are a detector-only rollout. Neither an old enforce
		// policy nor a high additive score may turn them into signal targets.
		if finding.DetectionOnly {
			finding.ResponseDecision = "detection_only"
			continue
		}
		if policy == nil {
			continue
		}
		if (policy.Response.Mode != "would_block" && policy.Response.Mode != "enforce") || !time.Now().Before(policy.ExpiresAt) {
			continue
		}
		if finding.RiskScore < policy.Response.RiskThreshold || finding.Confidence < policy.Response.MinConfidence {
			finding.ResponseDecision = "below_threshold"
			continue
		}
		finding.ResponseDecision = "would_block"
		required := append([]string(nil), policy.Response.RequiredCapabilities...)
		if policy.Response.Mode == "enforce" {
			required = append(required, "observation.process_exec", "observation.process_lineage", response.CapabilityName)
			finding.ResponseDecision = "terminate_pending"
		}
		for _, name := range required {
			capability, exists := report.Capabilities[name]
			if !exists || capability.Implementation != "implemented" || capability.RuntimeState != "active" || capability.VerifiedAt == nil {
				finding.ResponseDecision = "insufficient_capability"
				break
			}
		}
	}
}
