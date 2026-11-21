package agent

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"xe-antishell/internal/storage"
	"xe-antishell/internal/updates"
)

// ManagementAction is invoked only by the root-authorized Unix API. Secret
// enrollment/recovery values must never be forwarded to the monitoring panel.
func (s *Service) ManagementAction(ctx context.Context, action string, input json.RawMessage) (any, error) {
	switch action {
	case "status":
		return s.ManagedStatus(ctx)
	case "update-identity":
		state, err := s.store.ManagedState(ctx)
		if err != nil {
			return nil, err
		}
		return updates.Identity{AgentID: state.AgentID, EnrollmentID: state.EnrollmentID, KeyID: state.PolicyKeyID, PublicKey: state.PolicyPublicKey}, nil
	case "enroll":
		var request struct {
			URL          string `json:"url"`
			AgentID      string `json:"agent_id"`
			CAPEM        string `json:"ca_pem"`
			Token        string `json:"token"`
			RecoveryCode string `json:"recovery_code"`
		}
		if err := managed.DecodeStrict(input, 128<<10, &request); err != nil {
			return nil, err
		}
		if request.RecoveryCode == "" {
			return nil, errors.New("a durably saved recovery code is required before enrollment")
		}
		_, err := s.EnrollWithRecovery(ctx, request.URL, request.AgentID, []byte(request.CAPEM), request.Token, request.RecoveryCode)
		if err != nil {
			return nil, err
		}
		if err := s.store.BackfillDelivery(ctx, 1000); err != nil {
			s.managedError("history", "historical catch-up incomplete; new events continue delivery")
		} else {
			s.managedError("history", "")
		}
		return map[string]bool{"enrolled": true}, nil
	case "challenge":
		return s.store.CreateRemoval(ctx)
	case "authorize":
		var request struct {
			OperationID string                      `json:"operation_id"`
			Grant       *managed.SignedRemovalGrant `json:"grant,omitempty"`
			Recovery    string                      `json:"recovery,omitempty"`
		}
		if err := managed.DecodeStrict(input, 32<<10, &request); err != nil {
			return nil, err
		}
		op, err := s.store.AuthorizeRemoval(ctx, request.OperationID, request.Grant, request.Recovery)
		if err != nil {
			return nil, err
		}
		if op.Mode != "recovery" {
			if err := s.FlushManaged(ctx); err != nil {
				return nil, errors.New("authorization saved; retry after central delivery recovers")
			}
		}
		return op, nil
	case "remote-removal-check":
		if err := s.prepareRemoteRemovalExecution(ctx, input); err != nil {
			return nil, err
		}
		return map[string]bool{"allowed": true}, nil
	case "removal-check":
		var request struct {
			OperationID json.RawMessage `json:"operation_id,omitempty"`
		}
		if len(input) != 0 && string(input) != "null" {
			if err := managed.DecodeStrict(input, 4<<10, &request); err != nil {
				return nil, err
			}
		}
		var activeOperation string
		if s.remoteRemovalSupported() {
			var err error
			activeOperation, err = s.updateManager.RemoteRemovalRPMOperation()
			if err != nil {
				return nil, err
			}
		}
		if len(request.OperationID) != 0 {
			var operationID string
			if !s.remoteRemovalEnabled() || json.Unmarshal(request.OperationID, &operationID) != nil || operationID == "" {
				return nil, errors.New("remote removal is not enabled or the operation ID is missing")
			}
			if operationID != activeOperation {
				return nil, errors.New("remote removal does not match the active package transaction")
			}
			if err := s.store.CheckRemoteRemoval(ctx, operationID); err != nil {
				return nil, err
			}
			return map[string]bool{"allowed": true}, nil
		}
		if activeOperation != "" {
			return nil, errors.New("the active package transaction requires its remote removal operation ID")
		}
		if _, err := s.store.ManagedState(ctx); errors.Is(err, storage.ErrNotFound) {
			return map[string]bool{"allowed": true}, nil
		} else if err != nil {
			return nil, err
		}
		op, err := s.store.BeginRemoval(ctx)
		if err != nil {
			return nil, err
		}
		if op.Mode != "recovery" {
			if err := s.FlushManaged(ctx); err != nil {
				return nil, errors.New("removal start audit awaits central acknowledgement")
			}
		}
		return map[string]bool{"allowed": true, "offline_recovery": op.Mode == "recovery"}, nil
	default:
		return nil, errors.New("unsupported management action")
	}
}
