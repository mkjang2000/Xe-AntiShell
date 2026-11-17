package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"xe-antishell/internal/config"
	"xe-antishell/internal/updates"
)

func TestUpdateIdentityUsesDurableCurrentPublicTrustOnly(t *testing.T) {
	service, store := newTestService(t, config.CollectorDisabled, nil)
	defer store.Close()
	state, _, _ := managedPolicyFixture(t)
	state.KeyPEM = "PRIVATE_KEY_MUST_NOT_LEAVE_DATABASE"
	state.CertificatePEM = "CERTIFICATE_NOT_NEEDED_FOR_HELPER"
	if err := store.SaveManagedState(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	service.managedRuntime.enrollment.PolicyPublicKey = "stale cached key"
	value, err := service.ManagementAction(context.Background(), "update-identity", nil)
	if err != nil {
		t.Fatal(err)
	}
	identity, ok := value.(updates.Identity)
	if !ok || identity.AgentID != state.AgentID || identity.EnrollmentID != state.EnrollmentID || identity.KeyID != state.PolicyKeyID || identity.PublicKey != state.PolicyPublicKey {
		t.Fatalf("helper received stale trust: %#v", value)
	}
	data, _ := json.Marshal(value)
	if bytes.Contains(data, []byte("PRIVATE")) || bytes.Contains(data, []byte("CERTIFICATE")) {
		t.Fatal("private enrollment material escaped")
	}
}

func TestUpdateErrorsRemainIndependentOfHealthyPolicyAndHeartbeat(t *testing.T) {
	service, store := newTestService(t, config.CollectorDisabled, nil)
	defer store.Close()
	service.managedError("update", "central update operation pending; local journal retained")
	service.managedError("policy", "")
	service.managedError("heartbeat", "")
	service.managedRuntime.mu.RLock()
	defer service.managedRuntime.mu.RUnlock()
	if service.managedRuntime.status.LastError != "central update operation pending; local journal retained" {
		t.Fatal("healthy unrelated loop erased update error")
	}
}
