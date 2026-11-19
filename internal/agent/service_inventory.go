package agent

import (
	"context"
	"encoding/json"
	"time"

	"xe-antishell/internal/model"
)

const (
	serviceInventoryInterval = time.Minute
	serviceInventoryTimeout  = 2 * time.Second
	serviceInventoryMaxAge   = 3 * serviceInventoryInterval
	serviceInventoryMaxBytes = 8 << 10
)

type serviceInventorySource interface {
	ListeningServices(context.Context) model.ServiceInventory
}

type serviceInventorySnapshot struct {
	sampledAt time.Time
	state     string
	body      string
}

func (s *Service) startServiceInventory(ctx context.Context) {
	source, ok := s.processSource.(serviceInventorySource)
	if !ok {
		return
	}
	s.producerWG.Add(1)
	go func() {
		defer s.producerWG.Done()
		if !managedWait(ctx, 2*time.Second) {
			return
		}
		for ctx.Err() == nil {
			scan, cancel := context.WithTimeout(ctx, serviceInventoryTimeout)
			value := source.ListeningServices(scan)
			cancel()
			if ctx.Err() != nil {
				return
			}
			s.serviceInventory.Store(encodeServiceInventory(value))
			if !managedWait(ctx, serviceInventoryInterval) {
				return
			}
		}
	}()
}

func encodeServiceInventory(value model.ServiceInventory) *serviceInventorySnapshot {
	if value.Listeners == nil {
		value.Listeners = []model.ServiceListener{}
	}
	if len(value.Listeners) > model.MaxServiceInventoryListeners {
		value.Listeners = value.Listeners[:model.MaxServiceInventoryListeners]
		value.State = "partial"
	}
	for {
		body, err := json.Marshal(value)
		if err != nil {
			return &serviceInventorySnapshot{state: "unavailable"}
		}
		// The snapshot travels as a string in the existing capability map.
		quoted, _ := json.Marshal(string(body))
		if len(quoted) <= serviceInventoryMaxBytes {
			return &serviceInventorySnapshot{sampledAt: value.SampledAt, state: value.State, body: string(body)}
		}
		value.Listeners = value.Listeners[:len(value.Listeners)-1]
		value.State = "partial"
	}
}

func (s *Service) addServiceInventory(report *model.CapabilityReport, now time.Time) {
	if _, ok := s.processSource.(serviceInventorySource); !ok {
		return
	}
	name := model.ServiceInventoryCapability
	capability := model.Capability{
		Name: name, Provider: "procfs", Implementation: "implemented",
		Reason: "TCP listener inventory",
		State:  model.CapabilityLimited, RuntimeState: "unverified",
		Details: map[string]string{"contract": model.ServiceInventoryContract, "state": "pending"},
	}
	if value := s.serviceInventory.Load(); value != nil {
		capability.Details["state"] = value.state
		if value.body != "" {
			capability.Details["snapshot"] = value.body
		}
		switch {
		case value.sampledAt.IsZero() || value.state == "unavailable":
			capability.State = model.CapabilityError
			capability.RuntimeState = "error"
			capability.RuntimeReason = "TCP listener inventory could not be read"
		case now.Sub(value.sampledAt) > serviceInventoryMaxAge || now.Before(value.sampledAt.Add(-5*time.Second)):
			capability.Details["state"] = "stale"
			capability.RuntimeReason = "TCP listener inventory is out of date"
		default:
			at := value.sampledAt
			capability.VerifiedAt = &at
			if value.state == "complete" {
				capability.State = model.CapabilitySupported
				capability.RuntimeState = "available"
			} else {
				capability.RuntimeReason = "TCP listener inventory is partial"
			}
		}
	}
	report.Capabilities[name] = capability
}
