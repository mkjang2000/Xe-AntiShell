package model

import "encoding/json"

type HistoryQuery struct {
	Kind             string `json:"kind"`
	Service          string `json:"service,omitempty"`
	Search           string `json:"q,omitempty"`
	Severity         string `json:"severity,omitempty"`
	Cursor           string `json:"cursor,omitempty"`
	Limit            int    `json:"limit,omitempty"`
	ExcludeSelfTests bool   `json:"exclude_self_tests,omitempty"`
}

type HistoryPage struct {
	Items      json.RawMessage `json:"items"`
	NextCursor string          `json:"next_cursor"`
	HasMore    bool            `json:"has_more"`
	Total      int             `json:"total"`
}

type ServiceSummary struct {
	Name         string `json:"name"`
	FindingCount int    `json:"finding_count"`
	EventCount   int    `json:"event_count"`
}
