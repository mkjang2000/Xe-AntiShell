package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"xe-antishell/internal/config"
	"xe-antishell/internal/model"
)

type testServiceInventorySource struct {
	staticProcessSource
}

func (testServiceInventorySource) ListeningServices(context.Context) model.ServiceInventory {
	return model.ServiceInventory{
		SampledAt: time.Now().UTC(),
		State:     "complete",
		Listeners: []model.ServiceListener{{Service: "nginx.service", Port: 443, Family: "ipv4", Binding: "wildcard"}},
	}
}

func TestServiceInventoryStatusIsIndependentOfResponseEvidence(t *testing.T) {
	ctx := context.Background()
	service, store := newTestService(t, config.CollectorDisabled, nil)
	defer store.Close()
	source := testServiceInventorySource{}
	service.processSource = source
	value := source.ListeningServices(ctx)
	status, err := service.Status(ctx)
	if err != nil || status.CapabilityReport.Capabilities[model.ServiceInventoryCapability].Details["state"] != "pending" {
		t.Fatal("expected a pending report before the first scan")
	}
	service.serviceInventory.Store(encodeServiceInventory(value))
	report, err := service.Capabilities(ctx)
	capability := report.Capabilities[model.ServiceInventoryCapability]
	if err != nil || capability.RuntimeState != "available" || capability.VerifiedAt == nil ||
		capability.Details["contract"] != model.ServiceInventoryContract || !capability.VerifiedAt.Equal(value.SampledAt) {
		t.Fatalf("incorrect capability receipt: %#v / %v", capability, err)
	}
	var decoded model.ServiceInventory
	if err := json.Unmarshal([]byte(capability.Details["snapshot"]), &decoded); err != nil ||
		len(decoded.Listeners) != 1 || decoded.Listeners[0] != value.Listeners[0] {
		t.Fatalf("incorrect inventory snapshot: %#v / %v", decoded, err)
	}
	_, responseReport := service.runtimeSnapshot()
	if _, ok := responseReport.Capabilities[model.ServiceInventoryCapability]; ok {
		t.Fatal("a listening port became enforcement evidence")
	}
	value.SampledAt = time.Now().UTC().Add(-serviceInventoryMaxAge - time.Second)
	service.serviceInventory.Store(encodeServiceInventory(value))
	report, _ = service.Capabilities(ctx)
	stale := report.Capabilities[model.ServiceInventoryCapability]
	if stale.Details["state"] != "stale" || stale.VerifiedAt != nil {
		t.Fatalf("stale observation shown as verified: %#v", stale)
	}
	value.State, value.Listeners = "unavailable", nil
	service.serviceInventory.Store(encodeServiceInventory(value))
	report, _ = service.Capabilities(ctx)
	unavailable := report.Capabilities[model.ServiceInventoryCapability]
	if unavailable.Details["state"] != "unavailable" || unavailable.RuntimeState != "error" || unavailable.VerifiedAt != nil {
		t.Fatalf("unavailable scan shown as verified: %#v", unavailable)
	}
}

func TestServiceInventoryWireBudgetIncludesEscaping(t *testing.T) {
	value := model.ServiceInventory{
		SampledAt: time.Now().UTC(),
		State:     "complete",
		Listeners: make([]model.ServiceListener, model.MaxServiceInventoryListeners),
	}
	for i := range value.Listeners {
		value.Listeners[i] = model.ServiceListener{
			Service: strings.Repeat(`\x2d`, 60) + ".service",
			Port:    uint16(1000 + i), Family: "ipv6", Binding: "interface",
		}
	}
	snapshot := encodeServiceInventory(value)
	quoted, _ := json.Marshal(snapshot.body)
	var decoded model.ServiceInventory
	if err := json.Unmarshal([]byte(snapshot.body), &decoded); err != nil ||
		len(quoted) > serviceInventoryMaxBytes || decoded.State != "partial" ||
		len(decoded.Listeners) < 1 || len(decoded.Listeners) >= len(value.Listeners) ||
		decoded.Listeners[0] != value.Listeners[0] {
		t.Fatalf("wire limit not enforced: %d bytes, %d listeners, state %q / %v", len(quoted), len(decoded.Listeners), decoded.State, err)
	}
}
