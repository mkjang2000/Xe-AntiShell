// Package model contains the versioned, collector-independent domain model.
package model

import (
	"encoding/json"
	"time"
)

const SchemaVersion = "0.1"

const UnknownCredentialID int64 = -1

// Platform describes the host observed by a capability probe. Distribution
// metadata is informational; capability checks, not the distribution name,
// determine which collectors and rules can run.
type Platform struct {
	Distribution  string `json:"distribution" yaml:"distribution"`
	VersionID     string `json:"version_id" yaml:"version_id"`
	PrettyName    string `json:"pretty_name" yaml:"pretty_name"`
	KernelRelease string `json:"kernel_release" yaml:"kernel_release"`
	Architecture  string `json:"architecture" yaml:"architecture"`
	BootID        string `json:"boot_id" yaml:"boot_id"`
	Hostname      string `json:"hostname" yaml:"hostname"`
}

type CapabilityState string

const (
	CapabilitySupported   CapabilityState = "supported"
	CapabilityLimited     CapabilityState = "limited"
	CapabilityUnsupported CapabilityState = "unsupported"
	CapabilityError       CapabilityState = "error"
)

func (s CapabilityState) Valid() bool {
	switch s {
	case CapabilitySupported, CapabilityLimited, CapabilityUnsupported, CapabilityError:
		return true
	default:
		return false
	}
}

// Capability records both the passive prerequisite result and optional live
// agent evidence. State/Reason describe the probe; RuntimeState/RuntimeReason
// describe selected-source observations. Details must not contain secrets
// because reports are exposed through the local API.
type Capability struct {
	Name           string            `json:"name" yaml:"name"`
	State          CapabilityState   `json:"state" yaml:"state"`
	Provider       string            `json:"provider,omitempty" yaml:"provider,omitempty"`
	Reason         string            `json:"reason,omitempty" yaml:"reason,omitempty"`
	Details        map[string]string `json:"details,omitempty" yaml:"details,omitempty"`
	Implementation string            `json:"implementation,omitempty" yaml:"implementation,omitempty"`
	RuntimeState   string            `json:"runtime_state,omitempty" yaml:"runtime_state,omitempty"`
	RuntimeReason  string            `json:"runtime_reason,omitempty" yaml:"runtime_reason,omitempty"`
	VerifiedAt     *time.Time        `json:"verified_at,omitempty" yaml:"verified_at,omitempty"`
}

type CapabilityReport struct {
	ProbeVersion string                `json:"probe_version" yaml:"probe_version"`
	ProbedAt     time.Time             `json:"probed_at" yaml:"probed_at"`
	Platform     Platform              `json:"platform" yaml:"platform"`
	Capabilities map[string]Capability `json:"capabilities" yaml:"capabilities"`
}

func (r CapabilityReport) Capability(name string) (Capability, bool) {
	c, ok := r.Capabilities[name]
	return c, ok
}

type Completeness string

const (
	CompletenessComplete   Completeness = "complete"
	CompletenessPartial    Completeness = "partial"
	CompletenessIncomplete Completeness = "incomplete"
)

type LineageConfidence string

const (
	LineageVerified LineageConfidence = "verified"
	LineageInferred LineageConfidence = "inferred"
	LineageUnknown  LineageConfidence = "unknown"
)

// Process is a boot-scoped process observation. Unknown numeric credential
// fields use -1 so that UID 0 remains unambiguous.
type Process struct {
	Key               string              `json:"key" yaml:"key"`
	ParentKey         string              `json:"parent_key,omitempty" yaml:"parent_key,omitempty"`
	ExecID            string              `json:"exec_id,omitempty" yaml:"exec_id,omitempty"`
	PID               int                 `json:"pid" yaml:"pid"`
	TID               int                 `json:"tid,omitempty" yaml:"tid,omitempty"`
	Credentials       *CredentialSnapshot `json:"credentials,omitempty" yaml:"credentials,omitempty"`
	ExecPrivileges    *ExecPrivileges     `json:"exec_privileges,omitempty" yaml:"exec_privileges,omitempty"`
	PPID              int                 `json:"ppid" yaml:"ppid"`
	StartTime         time.Time           `json:"start_time" yaml:"start_time"`
	Exe               string              `json:"exe" yaml:"exe"`
	Argv              []string            `json:"argv,omitempty" yaml:"argv,omitempty"`
	UID               int64               `json:"uid" yaml:"uid"`
	EUID              int64               `json:"euid" yaml:"euid"`
	GID               int64               `json:"gid" yaml:"gid"`
	EGID              int64               `json:"egid" yaml:"egid"`
	CWD               string              `json:"cwd,omitempty" yaml:"cwd,omitempty"`
	OriginService     string              `json:"origin_service,omitempty" yaml:"origin_service,omitempty"`
	LineageConfidence LineageConfidence   `json:"lineage_confidence" yaml:"lineage_confidence"`
	Complete          bool                `json:"complete" yaml:"complete"`
	FirstSeen         time.Time           `json:"first_seen" yaml:"first_seen"`
	LastSeen          time.Time           `json:"last_seen" yaml:"last_seen"`
	ExitedAt          *time.Time          `json:"exited_at,omitempty" yaml:"exited_at,omitempty"`
}

type Event struct {
	SchemaVersion   string       `json:"schema_version" yaml:"schema_version"`
	ID              string       `json:"event_id" yaml:"event_id"`
	HostID          string       `json:"host_id" yaml:"host_id"`
	BootID          string       `json:"boot_id" yaml:"boot_id"`
	StreamID        string       `json:"stream_id" yaml:"stream_id"`
	Sequence        uint64       `json:"sequence" yaml:"sequence"`
	EventTime       time.Time    `json:"event_time" yaml:"event_time"`
	IngestTime      time.Time    `json:"ingest_time" yaml:"ingest_time"`
	Type            string       `json:"event_type" yaml:"event_type"`
	Source          string       `json:"source" yaml:"source"`
	SourceEventID   string       `json:"source_event_id,omitempty" yaml:"source_event_id,omitempty"`
	Completeness    Completeness `json:"completeness" yaml:"completeness"`
	MissingFields   []string     `json:"missing_fields,omitempty" yaml:"missing_fields,omitempty"`
	TruncatedFields []string     `json:"truncated_fields,omitempty" yaml:"truncated_fields,omitempty"`
	RedactedFields  []string     `json:"redacted_fields,omitempty" yaml:"redacted_fields,omitempty"`
	Process         Process      `json:"process" yaml:"process"`
	// Ancestors are bounded source-provided process snapshots, nearest first.
	// They provide context and are not additional execution events.
	Ancestors  []Process              `json:"ancestors,omitempty" yaml:"ancestors,omitempty"`
	RawJSON    json.RawMessage        `json:"raw_json,omitempty" yaml:"raw_json,omitempty"`
	Execution  *ExecutionObservation  `json:"execution,omitempty" yaml:"execution,omitempty"`
	File       *FileObservation       `json:"file,omitempty" yaml:"file,omitempty"`
	Network    *NetworkObservation    `json:"network,omitempty" yaml:"network,omitempty"`
	Credential *CredentialObservation `json:"credential,omitempty" yaml:"credential,omitempty"`
}

// RiskFactor is a bounded rule contribution, not a probability of compromise.
// IDs describe fixed observations and must never include command contents.
type RiskFactor struct {
	ID    string `json:"id" yaml:"id"`
	Score int    `json:"score" yaml:"score"`
}

type Finding struct {
	ID               string       `json:"finding_id" yaml:"finding_id"`
	RuleID           string       `json:"rule_id" yaml:"rule_id"`
	RuleVersion      string       `json:"rule_version" yaml:"rule_version"`
	CreatedAt        time.Time    `json:"created_at" yaml:"created_at"`
	Severity         string       `json:"severity" yaml:"severity"`
	Confidence       float64      `json:"confidence" yaml:"confidence"`
	State            string       `json:"state" yaml:"state"`
	Summary          string       `json:"summary" yaml:"summary"`
	ProcessKey       string       `json:"process_key,omitempty" yaml:"process_key,omitempty"`
	EvidenceEventIDs []string     `json:"evidence_event_ids" yaml:"evidence_event_ids"`
	Source           string       `json:"source" yaml:"source"`
	OriginService    string       `json:"origin_service,omitempty" yaml:"origin_service,omitempty"`
	RiskScore        int          `json:"risk_score,omitempty" yaml:"risk_score,omitempty"`
	ResponseDecision string       `json:"response_decision,omitempty" yaml:"response_decision,omitempty"`
	PolicyRevision   uint64       `json:"policy_revision,omitempty" yaml:"policy_revision,omitempty"`
	RiskFactors      []RiskFactor `json:"risk_factors,omitempty" yaml:"risk_factors,omitempty"`
	DetectionOnly    bool         `json:"detection_only,omitempty" yaml:"detection_only,omitempty"`

	ApplicationPolicyID      string `json:"application_policy_id,omitempty" yaml:"application_policy_id,omitempty"`
	ApplicationPolicyVersion uint64 `json:"application_policy_version,omitempty" yaml:"application_policy_version,omitempty"`
	ApplicationService       string `json:"application_service,omitempty" yaml:"application_service,omitempty"`
}

type AgentMode string

const (
	AgentModeActive      AgentMode = "active"
	AgentModeDegraded    AgentMode = "degraded"
	AgentModeUnsupported AgentMode = "unsupported"
	AgentModeError       AgentMode = "error"
)

type Health string

const (
	HealthStarting Health = "starting"
	HealthHealthy  Health = "healthy"
	HealthDegraded Health = "degraded"
	HealthError    Health = "error"
)

type AgentStatus struct {
	Version          string            `json:"version" yaml:"version"`
	Mode             AgentMode         `json:"mode" yaml:"mode"`
	Collector        string            `json:"collector,omitempty" yaml:"collector,omitempty"`
	Health           Health            `json:"health" yaml:"health"`
	StartedAt        time.Time         `json:"started_at" yaml:"started_at"`
	LastEventAt      *time.Time        `json:"last_event_at,omitempty" yaml:"last_event_at,omitempty"`
	Dropped          uint64            `json:"dropped" yaml:"dropped"`
	ParseErrors      uint64            `json:"parse_errors" yaml:"parse_errors"`
	LastError        string            `json:"last_error,omitempty" yaml:"last_error,omitempty"`
	CapabilityReport *CapabilityReport `json:"capability_report,omitempty" yaml:"capability_report,omitempty"`
	CollectorHealth  *CollectorHealth  `json:"collector_health,omitempty" yaml:"collector_health,omitempty"`
}

// CollectorHealth describes the selected source stream separately from the
// agent's queue/persistence counters. Skipped events are unsupported source
// message types, not a claim that kernel telemetry was lost.
type CollectorHealth struct {
	Name           string     `json:"name" yaml:"name"`
	Running        bool       `json:"running" yaml:"running"`
	EventsReceived uint64     `json:"events_received" yaml:"events_received"`
	EventsEmitted  uint64     `json:"events_emitted" yaml:"events_emitted"`
	EventsSkipped  uint64     `json:"events_skipped" yaml:"events_skipped"`
	ParseErrors    uint64     `json:"parse_errors" yaml:"parse_errors"`
	LastEventAt    *time.Time `json:"last_event_at,omitempty" yaml:"last_event_at,omitempty"`
	LastError      string     `json:"last_error,omitempty" yaml:"last_error,omitempty"`
}
