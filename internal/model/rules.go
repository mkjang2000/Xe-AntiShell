package model

import (
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

// DirectServiceEvidence identifies missing direct service attribution when the
// recorded origin was inferred from lineage. This survives JSONL round trips.
const DirectServiceEvidence = "process.direct_service"

// RuleCatalog reports the policy snapshot published by the running detector.
type RuleCatalog struct {
	EvaluatedAt              time.Time    `json:"evaluated_at"`
	PolicySource             string       `json:"policy_source"`
	ServiceObservationSource string       `json:"service_observation_source,omitempty"`
	PolicyRevision           uint64       `json:"policy_revision"`
	Collector                string       `json:"collector"`
	Rules                    []RuleStatus `json:"rules"`
}

// ServiceRuleStatus records the configured selection independent of the
// profile and sensor prerequisites shown in RuleStatus.
type ServiceRuleStatus struct {
	managed.ServiceRuleControl
	Suppressed bool `json:"suppressed"`
}

// Enabled denotes policy eligibility. Sensor receipts and response thresholds
// are independent, and are checked again for each event.
type RuleStatus struct {
	ServiceControls []ServiceRuleStatus `json:"service_controls,omitempty"`
	ID              string              `json:"id"`
	Version         string              `json:"version"`
	Title           string              `json:"title"`
	Description     string              `json:"description"`
	Profile         string              `json:"profile"`
	EventTypes      []string            `json:"event_types"`
	RequiredFields  []string            `json:"required_fields"`
	Sensors         []RuleSensor        `json:"sensors"`
	Enabled         bool                `json:"enabled"`
	Reason          string              `json:"reason,omitempty"`
	Response        string              `json:"response"`
}

type RuleSensor struct {
	Name              string     `json:"name"`
	RequiredCollector string     `json:"required_collector,omitempty"`
	State             string     `json:"state"`
	VerifiedAt        *time.Time `json:"verified_at,omitempty"`
}
