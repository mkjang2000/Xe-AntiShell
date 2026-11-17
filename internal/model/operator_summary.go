package model

import "time"

// OperatorSummary reports retained evidence, not a bounded recent API sample.
// Finding counts exclude the named detection self-test; event counts include
// every retained event. Missing summaries must not be rendered as zero counts.
type OperatorSummary struct {
	AsOf                 time.Time `json:"as_of"`
	WindowStart          time.Time `json:"window_start"`
	TotalEvents          int       `json:"total_events"`
	Events24H            int       `json:"events_24h"`
	TotalFindings        int       `json:"total_findings"`
	OpenFindings         int       `json:"open_findings"`
	Findings24H          int       `json:"findings_24h"`
	SelfTestFindings     int       `json:"self_test_findings"`
	CriticalOpen         int       `json:"critical_open"`
	HighOpen             int       `json:"high_open"`
	OtherOpen            int       `json:"other_open"`
	DetectionEnabled     bool      `json:"detection_enabled"`
	ExtendedProcessRules bool      `json:"extended_process_rules"`
	ResponseMode         string    `json:"response_mode"`
	ResponseAction       string    `json:"response_action"`
	RecentFindings       []Finding `json:"recent_findings"`
}
