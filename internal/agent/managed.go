package agent

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"xe-antishell/internal/managedclient"
	"xe-antishell/internal/storage"
)

type ManagedStatus struct {
	Enrolled      bool                   `json:"enrolled"`
	AgentID       string                 `json:"agent_id,omitempty"`
	EnrollmentID  string                 `json:"enrollment_id,omitempty"`
	CentralURL    string                 `json:"central_url,omitempty"`
	Delivery      storage.DeliveryStatus `json:"delivery"`
	Policy        managed.PolicyStatus   `json:"policy"`
	LastContactAt *time.Time             `json:"last_contact_at,omitempty"`
	LastError     string                 `json:"last_error,omitempty"`
}

type managedRuntime struct {
	mu              sync.RWMutex
	initializeMu    sync.Mutex
	enrollmentMu    sync.Mutex
	senderMu        sync.Mutex
	policyMu        sync.Mutex
	client          *managedclient.Client
	enrollment      storage.ManagedState
	status          ManagedStatus
	operationErrors map[string]string
}

func newManagedRuntime() *managedRuntime {
	return &managedRuntime{status: ManagedStatus{Policy: managed.PolicyStatus{Result: "local"}}}
}

func (s *Service) ManagedStatus(ctx context.Context) (ManagedStatus, error) {
	_, _, err := s.managedConnection(ctx)
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		return ManagedStatus{}, err
	}
	s.managedRuntime.mu.RLock()
	status := s.managedRuntime.status
	if status.LastContactAt != nil {
		at := *status.LastContactAt
		status.LastContactAt = &at
	}
	if status.Policy.AppliedAt != nil {
		at := *status.Policy.AppliedAt
		status.Policy.AppliedAt = &at
	}
	s.managedRuntime.mu.RUnlock()
	if !status.Enrolled {
		return status, nil
	}
	status.Delivery, err = s.store.DeliveryStatus(ctx)
	return status, err
}

func (s *Service) managedConnection(ctx context.Context) (*managedclient.Client, storage.ManagedState, error) {
	runtime := s.managedRuntime
	runtime.initializeMu.Lock()
	defer runtime.initializeMu.Unlock()
	runtime.mu.RLock()
	client, state := runtime.client, runtime.enrollment
	runtime.mu.RUnlock()
	if client != nil {
		return client, state, nil
	}
	state, err := s.store.ManagedState(ctx)
	if err != nil {
		return nil, state, err
	}
	client, err = managedclient.New(state.URL, []byte(state.CAPEM), []byte(state.CertificatePEM), []byte(state.KeyPEM))
	if err != nil {
		return nil, state, errors.New("stored central identity is invalid")
	}
	runtime.mu.Lock()
	runtime.client, runtime.enrollment = client, state
	runtime.status.Enrolled, runtime.status.AgentID, runtime.status.EnrollmentID, runtime.status.CentralURL = true, state.AgentID, state.EnrollmentID, state.URL
	runtime.mu.Unlock()
	s.managedError("identity", "")
	return client, state, nil
}

// Enroll persists the private key and CSR before contacting the central service.
// A retry therefore presents the same identity after a lost network response.
// The recovery code is returned once; only its bound verifier is retained.
func (s *Service) Enroll(ctx context.Context, url, agentID string, caPEM []byte, token string) (string, error) {
	code, err := managed.NewChallenge()
	if err != nil {
		return "", err
	}
	return s.EnrollWithRecovery(ctx, url, agentID, caPEM, token, code)
}

func (s *Service) EnrollWithRecovery(ctx context.Context, url, agentID string, caPEM []byte, token, code string) (string, error) {
	runtime := s.managedRuntime
	runtime.enrollmentMu.Lock()
	defer runtime.enrollmentMu.Unlock()
	if _, err := managed.NewRecoveryVerifier(agentID, "pending", code); err != nil {
		return "", err
	}
	if existing, err := s.store.ManagedState(ctx); err == nil {
		if existing.URL == url && existing.AgentID == agentID && bytes.Equal([]byte(existing.CAPEM), caPEM) && managed.VerifyRecoveryCode(existing.Recovery, agentID, existing.EnrollmentID, code) {
			return code, nil
		}
		return "", errors.New("agent is already enrolled with a different identity or recovery code")
	} else if !errors.Is(err, storage.ErrNotFound) {
		return "", err
	}
	client, err := managedclient.New(url, caPEM, nil, nil)
	if err != nil {
		return "", err
	}
	defer client.Close()
	pending, err := s.store.PendingEnrollment(ctx)
	if errors.Is(err, storage.ErrNotFound) {
		keyPEM, csrPEM, err := managedclient.GenerateCSR(agentID)
		if err != nil {
			return "", err
		}
		pending = storage.PendingEnrollment{URL: url, AgentID: agentID, CAPEM: string(caPEM), KeyPEM: string(keyPEM), CSRPEM: string(csrPEM)}
		if err := s.store.SavePendingEnrollment(ctx, pending); err != nil {
			return "", err
		}
	} else if err != nil {
		return "", err
	}
	if pending.URL != url || pending.AgentID != agentID || !bytes.Equal([]byte(pending.CAPEM), caPEM) {
		return "", errors.New("pending enrollment is pinned to a different central identity")
	}
	s.statusMu.RLock()
	hostname := s.report.Platform.Hostname
	s.statusMu.RUnlock()
	response, err := client.Enroll(ctx, token, managed.EnrollRequest{AgentID: agentID, CSRPEM: pending.CSRPEM, Hostname: hostname})
	if err != nil {
		return "", err
	}
	if err := managedclient.ValidateEnrollment(response, []byte(pending.KeyPEM), caPEM, agentID, time.Now()); err != nil {
		return "", err
	}
	verifier, err := managed.NewRecoveryVerifier(agentID, response.EnrollmentID, code)
	if err != nil {
		return "", err
	}
	state := storage.ManagedState{URL: url, AgentID: agentID, EnrollmentID: response.EnrollmentID, CAPEM: string(caPEM), CertificatePEM: response.CertificatePEM, KeyPEM: pending.KeyPEM, PolicyKeyID: response.PolicyKeyID, PolicyPublicKey: response.PolicyPublicKey, Recovery: verifier}
	if err := s.store.SaveManagedState(ctx, state); err != nil {
		return "", err
	}
	if _, _, err := s.managedConnection(ctx); err != nil {
		return "", err
	}
	return code, nil
}

// FlushManaged drains a bounded backlog while serializing ACKs with the normal
// sender. A caller must treat a nonempty backlog or network error as failure.
func (s *Service) FlushManaged(ctx context.Context) error {
	runtime := s.managedRuntime
	runtime.senderMu.Lock()
	defer runtime.senderMu.Unlock()
	for index := 0; index < 50; index++ {
		empty, err := s.deliverManagedBatch(ctx)
		if err != nil || empty {
			return err
		}
	}
	return errors.New("managed delivery backlog exceeds bounded flush")
}

func (s *Service) deliverManagedBatch(ctx context.Context) (empty bool, err error) {
	// Callers hold senderMu, keeping this operation's recovery/error transition
	// ordered across the background sender and administrative flushes.
	defer func() {
		if err == nil {
			s.managedError("delivery", "")
		} else if !errors.Is(err, storage.ErrNotFound) {
			s.managedError("delivery", "central event delivery failed; records retained for retry")
		}
	}()
	client, _, err := s.managedConnection(ctx)
	if err != nil {
		return false, err
	}
	batch, err := s.store.DeliveryBatch(ctx, 64)
	if err != nil {
		return false, err
	}
	if len(batch.Records) == 0 {
		return true, nil
	}
	ack, err := client.Ingest(ctx, batch)
	if err != nil {
		return false, err
	}
	if err := s.store.Acknowledge(ctx, ack, batch); err != nil {
		return false, err
	}
	s.managedContact()
	return false, nil
}

func (s *Service) managedContact() {
	now := time.Now().UTC()
	s.managedRuntime.mu.Lock()
	s.managedRuntime.status.LastContactAt = &now
	s.managedRuntime.mu.Unlock()
}

func (s *Service) managedError(operation, message string) {
	runtime := s.managedRuntime
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.operationErrors == nil {
		runtime.operationErrors = make(map[string]string)
	}
	if message == "" {
		delete(runtime.operationErrors, operation)
	} else {
		runtime.operationErrors[operation] = message
	}
	var active []string
	for _, name := range []string{"identity", "delivery", "heartbeat", "policy", "history"} {
		if message := runtime.operationErrors[name]; message != "" {
			active = append(active, message)
		}
	}
	runtime.status.LastError = strings.Join(active, "; ")
}
