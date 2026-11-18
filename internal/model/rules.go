package model

import "time"

// RuleCatalog reports the policy snapshot published by the running detector.
type RuleCatalog struct {
	PolicySource   string       `json:"policy_source"`
	PolicyRevision uint64       `json:"policy_revision"`
	Collector      string       `json:"collector"`
	Rules          []RuleStatus `json:"rules"`
}

// Enabled denotes policy eligibility. Sensor receipts and response thresholds
// are independent, and are checked again for each event.
type RuleStatus struct {
	ID             string       `json:"id"`
	Version        string       `json:"version"`
	Title          string       `json:"title"`
	Description    string       `json:"description"`
	Profile        string       `json:"profile"`
	EventTypes     []string     `json:"event_types"`
	RequiredFields []string     `json:"required_fields"`
	Sensors        []RuleSensor `json:"sensors"`
	Enabled        bool         `json:"enabled"`
	Reason         string       `json:"reason,omitempty"`
	Response       string       `json:"response"`
}

type RuleSensor struct {
	Name              string     `json:"name"`
	RequiredCollector string     `json:"required_collector,omitempty"`
	State             string     `json:"state"`
	VerifiedAt        *time.Time `json:"verified_at,omitempty"`
}
