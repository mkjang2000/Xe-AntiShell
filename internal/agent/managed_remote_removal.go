package agent

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"xe-antishell/internal/buildinfo"
	"xe-antishell/internal/managedclient"
	"xe-antishell/internal/model"
	"xe-antishell/internal/storage"
	"xe-antishell/internal/updates"
)

func (s *Service) remoteRemovalSupported() bool {
	return buildinfo.PackageRelease != "" && os.Geteuid() == 0 && s.config.SourceFile == updates.ConfigPath &&
		updates.StandardPaths(s.config.Agent.SocketPath, s.config.Agent.DatabasePath) && updates.RemoteRemovalSupported()
}

func (s *Service) remoteRemovalEnabled() bool {
	return s.config.Central.RemoteRemovalEnabled && s.remoteRemovalSupported()
}

func (s *Service) addRemoteRemovalCapability(report *model.CapabilityReport) {
	if !s.remoteRemovalSupported() {
		return
	}
	report.Capabilities[managed.RemoteRemovalCapability] = model.Capability{
		Name: managed.RemoteRemovalCapability, Provider: "agent", State: model.CapabilitySupported,
		Implementation: "implemented", RuntimeState: "available", Reason: "signed remote package removal is supported",
		Details: map[string]string{"contract": managed.RemoteRemovalContract, "enabled": strconv.FormatBool(s.config.Central.RemoteRemovalEnabled)},
	}
}

func (s *Service) managedRemoteRemovalLoop(ctx context.Context) {
	if !s.remoteRemovalSupported() {
		return
	}
	for {
		s.managedRemoteRemovalOnce(ctx)
		if !managedWait(ctx, 15*time.Second) {
			return
		}
	}
}

func (s *Service) managedRemoteRemovalOnce(ctx context.Context) {
	client, enrollment, err := s.managedConnection(ctx)
	if errors.Is(err, storage.ErrNotFound) {
		return
	}
	if err != nil {
		s.managedError("remote_removal", "remote removal identity unavailable")
		return
	}
	identity := updates.Identity{AgentID: enrollment.AgentID, EnrollmentID: enrollment.EnrollmentID, KeyID: enrollment.PolicyKeyID, PublicKey: enrollment.PolicyPublicKey}
	// An already attempted operation can need outcome reconciliation even after
	// the host's administrator turns off permission for new removals.
	if err := s.updateManager.RecoverRemoteRemoval(ctx, identity); err != nil && !errors.Is(err, updates.ErrBusy) {
		s.managedError("remote_removal", "remote removal outcome reconciliation pending")
		return
	}
	if !s.remoteRemovalEnabled() {
		return
	}
	signed, err := client.RemoteRemoval(ctx)
	if err == nil && signed != nil {
		err = s.stageRemoteRemoval(ctx, client, enrollment, *signed)
	}
	if err != nil && !errors.Is(err, updates.ErrBusy) {
		s.managedError("remote_removal", "remote removal preparation pending or rejected")
		return
	}
	s.managedError("remote_removal", "")
}

func (s *Service) stageRemoteRemoval(ctx context.Context, client *managedclient.Client, enrollment storage.ManagedState, signed managed.SignedRemoteRemovalOrder) error {
	order, err := verifyRemoteRemoval(signed, enrollment)
	if err != nil {
		return err
	}
	op, err := s.store.PrepareRemoteRemoval(ctx, order)
	if errors.Is(err, storage.ErrRemovalDenied) && op.State != "executing" {
		return client.ReportRemoteRemoval(ctx, managed.RemoteRemovalReport{OrderID: order.ID, State: "failed", Code: "local_gate"})
	}
	if err != nil {
		return err
	}
	if op.State == "prepared" {
		claim := managed.RemoteRemovalClaim{OrderID: order.ID, OperationID: op.ID, Challenge: op.Challenge}
		grant, err := client.ClaimRemoteRemoval(ctx, claim)
		if err != nil {
			return err
		}
		op, err = s.store.AuthorizeRemoteRemoval(ctx, op.ID, order, grant)
		if errors.Is(err, storage.ErrRemovalDenied) {
			return client.ReportRemoteRemoval(ctx, managed.RemoteRemovalReport{OrderID: order.ID, State: "failed", Code: "local_gate"})
		}
		if err != nil {
			return err
		}
	}
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	err = s.flushRemovalAudit(bounded, op.AuditSequence)
	cancel()
	if err != nil {
		return err
	}
	return s.updateManager.StageRemoteRemoval(ctx, signed, op.ID)
}

func verifyRemoteRemoval(signed managed.SignedRemoteRemovalOrder, enrollment storage.ManagedState) (managed.RemoteRemovalOrder, error) {
	key, err := managed.DecodePublicKey(enrollment.PolicyPublicKey)
	if err != nil {
		return managed.RemoteRemovalOrder{}, err
	}
	return managed.VerifyRemoteRemovalOrder(signed, map[string]ed25519.PublicKey{enrollment.PolicyKeyID: key}, enrollment.AgentID, enrollment.EnrollmentID, time.Now().UTC())
}

func (s *Service) prepareRemoteRemovalExecution(ctx context.Context, input json.RawMessage) error {
	if !s.remoteRemovalEnabled() {
		return errors.New("remote removal is not enabled")
	}
	var request struct {
		Order       managed.SignedRemoteRemovalOrder `json:"order"`
		OperationID string                           `json:"operation_id"`
	}
	if err := managed.DecodeStrict(input, 24<<10, &request); err != nil {
		return err
	}
	enrollment, err := s.store.ManagedState(ctx)
	if err != nil {
		return err
	}
	order, err := verifyRemoteRemoval(request.Order, enrollment)
	if err != nil {
		return err
	}
	op, err := s.store.BeginRemoteRemoval(ctx, request.OperationID, order.ID)
	if err != nil {
		return err
	}
	if err := s.flushRemovalAudit(ctx, op.AuditSequence); err != nil {
		return err
	}
	return s.store.CheckRemoteRemoval(ctx, request.OperationID)
}

// Stop flushing once the specific audit is acknowledged. Unrelated new events
// may continue to arrive while the removal operation is being prepared.
func (s *Service) flushRemovalAudit(ctx context.Context, sequence uint64) error {
	if sequence == 0 {
		return errors.New("remote removal audit sequence is missing")
	}
	runtime := s.managedRuntime
	runtime.senderMu.Lock()
	defer runtime.senderMu.Unlock()
	const maxBatches = 50
	for index := 0; index <= maxBatches; index++ {
		delivery, err := s.store.DeliveryStatus(ctx)
		if err != nil {
			return err
		}
		if delivery.Acknowledged >= sequence {
			return nil
		}
		if index == maxBatches {
			break
		}
		empty, err := s.deliverManagedBatch(ctx)
		if err != nil {
			return err
		}
		if empty {
			break
		}
	}
	return errors.New("remote removal audit has not been acknowledged")
}
