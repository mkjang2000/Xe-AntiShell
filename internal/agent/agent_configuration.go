package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"xe-antishell/internal/model"
	"xe-antishell/internal/storage"
)

const independentHeartbeatSeconds = 10

type agentConfigurationState struct {
	checkpoint storage.AgentConfigurationCheckpoint
	requested  uint64
	reason     string
}

func (s *Service) verifyAgentConfiguration(signed managed.SignedAgentConfiguration, enrolled storage.ManagedState, at time.Time) (managed.AgentConfiguration, error) {
	key, err := managed.DecodePublicKey(enrolled.PolicyPublicKey)
	if err != nil {
		return managed.AgentConfiguration{}, err
	}
	return managed.VerifyAgentConfiguration(signed, map[string]ed25519.PublicKey{enrolled.PolicyKeyID: key}, enrolled.AgentID, enrolled.EnrollmentID, at)
}

func (s *Service) restoreAgentConfiguration(ctx context.Context, enrolled storage.ManagedState) error {
	checkpoint, err := s.store.AgentConfiguration(ctx)
	if errors.Is(err, storage.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if checkpoint.Signed.Configuration.EnrollmentID != enrolled.EnrollmentID {
		return nil
	}
	signed := checkpoint.Signed
	// Expiry is an acceptance deadline. A durable successful decision remains
	// in effect on offline restart.
	value, err := s.verifyAgentConfiguration(signed, enrolled, checkpoint.AppliedAt)
	if err != nil {
		return err
	}
	s.agentConfiguration.Store(&agentConfigurationState{checkpoint: checkpoint, requested: value.Revision})
	return nil
}

func (s *Service) pollAgentConfiguration(ctx context.Context) {
	for {
		if client, enrolled, err := s.managedConnection(ctx); err == nil {
			if s.agentConfigurationRestoreFailed.Load() {
				s.agentConfigurationRestoreFailed.Store(s.restoreAgentConfiguration(ctx, enrolled) != nil)
			}
			if signed, err := client.AgentConfiguration(ctx); err == nil && signed != nil && !s.agentConfigurationRestoreFailed.Load() {
				s.applyAgentConfiguration(ctx, *signed, enrolled, time.Now().UTC())
			}
		}
		if !managedWait(ctx, 10*time.Second) {
			return
		}
	}
}

func (s *Service) applyAgentConfiguration(ctx context.Context, signed managed.SignedAgentConfiguration, enrolled storage.ManagedState, now time.Time) {
	s.agentConfigurationMu.Lock()
	defer s.agentConfigurationMu.Unlock()
	var current agentConfigurationState
	if loaded := s.agentConfiguration.Load(); loaded != nil {
		current = *loaded
	}
	previous := current.checkpoint.Signed.Configuration
	if previous.EnrollmentID != "" && previous.EnrollmentID != enrolled.EnrollmentID {
		return
	}
	if signed.Configuration.Revision <= previous.Revision || current.requested == signed.Configuration.Revision && current.reason != "" {
		return
	}
	value, err := s.verifyAgentConfiguration(signed, enrolled, now)
	reason := ""
	switch {
	case err != nil:
		reason = "verification_failed"
	case value.BaseRevision != previous.Revision:
		reason = "revision_conflict"
	case value.Set.Retention != nil && value.Set.Retention.ObservationHistoryMinutes > s.config.AgentConfiguration.MaxObservationHistoryMinutes:
		reason = "local_retention_limit"
	case s.effectiveRetentionMinutes(value) < s.effectiveRetentionMinutes(previous) && !value.RetentionReductionApproved:
		reason = "retention_reduction_not_approved"
	}
	if reason == "" {
		checkpoint := storage.AgentConfigurationCheckpoint{Signed: signed, AppliedAt: now, PanelGeneration: current.checkpoint.PanelGeneration}
		if panelChoice(previous) != panelChoice(value) {
			sum := sha256.Sum256([]byte(value.EnrollmentID + "/" + strconv.FormatUint(value.Revision, 10)))
			checkpoint.PanelGeneration = hex.EncodeToString(sum[:])
		}
		if err := s.store.SaveAgentConfiguration(ctx, checkpoint, previous.Revision); err != nil {
			reason = "local_persistence_failed"
		} else {
			s.agentConfiguration.Store(&agentConfigurationState{checkpoint: checkpoint, requested: value.Revision})
			s.wakeAgentConfigurationHeartbeat()
			return
		}
	}
	if ctx.Err() == nil && (current.requested != signed.Configuration.Revision || current.reason != reason) {
		current.requested, current.reason = signed.Configuration.Revision, reason
		s.agentConfiguration.Store(&current)
		s.wakeAgentConfigurationHeartbeat()
	}
}

func (s *Service) wakeAgentConfigurationHeartbeat() {
	select {
	case s.agentConfigurationHeartbeat <- struct{}{}:
	default:
	}
}

func panelChoice(value managed.AgentConfiguration) string {
	if value.Set.LocalPanel != nil {
		return value.Set.LocalPanel.Access
	}
	if slices.Contains(value.Inherit, managed.AgentConfigPanelKey) {
		return "inherit"
	}
	return ""
}

func (s *Service) PanelAccess(context.Context) (model.PanelAccess, error) {
	if s.agentConfigurationRestoreFailed.Load() {
		return model.PanelAccess{}, errors.New("approved panel access could not be verified")
	}
	result := model.PanelAccess{Access: "allow"}
	if state := s.agentConfiguration.Load(); state != nil {
		result.Generation = state.checkpoint.PanelGeneration
		if state.checkpoint.Signed.Configuration.Set.LocalPanel != nil {
			result.Access = state.checkpoint.Signed.Configuration.Set.LocalPanel.Access
		}
	}
	return result, nil
}

func (s *Service) approvedAgentConfiguration() managed.AgentConfiguration {
	if state := s.agentConfiguration.Load(); state != nil {
		return state.checkpoint.Signed.Configuration
	}
	return managed.AgentConfiguration{}
}

func (s *Service) observationHistoryMinutesFor(value managed.AgentConfiguration) int {
	if value.Set.Retention != nil && value.Set.Retention.ObservationHistoryMinutes <= s.config.AgentConfiguration.MaxObservationHistoryMinutes {
		return value.Set.Retention.ObservationHistoryMinutes
	}
	return s.config.Limits.ObservationHistoryMinutes
}

func (s *Service) observationHistoryMinutes() int {
	return s.observationHistoryMinutesFor(s.approvedAgentConfiguration())
}

func (s *Service) effectiveRetentionMinutes(value managed.AgentConfiguration) int {
	if minutes := s.observationHistoryMinutesFor(value); minutes > 0 {
		return minutes
	}
	return 1440 * s.config.Limits.RetentionDays
}

func (s *Service) addAgentConfiguration(report *model.CapabilityReport) {
	if s.agentConfigurationRestoreFailed.Load() {
		return
	}
	state := s.agentConfiguration.Load()
	value := managed.AgentConfiguration{}
	result := managed.AgentConfigurationReport{Result: "local"}
	if state != nil {
		value = state.checkpoint.Signed.Configuration
		result.RequestedRevision, result.AppliedRevision = state.requested, value.Revision
		if value.Revision > 0 {
			result.Result = "applied"
			at := state.checkpoint.AppliedAt
			result.AppliedAt = &at
		}
		if state.reason != "" {
			result.Result, result.Error = "rejected", state.reason
		}
	}
	result.Effective = s.agentConfigurationEffective(value)
	body, err := json.Marshal(result)
	if err != nil {
		return
	}
	report.Capabilities[managed.AgentConfigurationCapability] = model.Capability{
		Name: managed.AgentConfigurationCapability, State: model.CapabilitySupported,
		Provider: "managed", Implementation: "implemented", RuntimeState: "available",
		Details: map[string]string{"contract": managed.AgentConfigurationContract, "snapshot": string(body)},
	}
}
