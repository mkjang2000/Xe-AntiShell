package model

import "time"

const (
	ServiceInventoryCapability   = "inventory.listening_services"
	ServiceInventoryContract     = "1"
	MaxServiceInventoryListeners = 64
)

// ServiceInventory describes TCP listeners in the agent's network namespace
// at the time of a bounded observation.
type ServiceInventory struct {
	SampledAt time.Time         `json:"sampled_at"`
	State     string            `json:"state"`
	Listeners []ServiceListener `json:"listeners"`
}

// Service is empty when a direct host systemd service cannot be established.
// Binding classifies the local address without disclosing it.
type ServiceListener struct {
	Service string `json:"service,omitempty"`
	Port    uint16 `json:"port"`
	Family  string `json:"family"`
	Binding string `json:"binding"`
}
