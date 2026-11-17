// Package model preserves agent-local imports of the shared protocol model.
// Agent-only history and operator summaries remain in this package.
package model

import shared "github.com/mkjang2000/Xe-AntiShell/protocol/model"

const (
	SchemaVersion        = shared.SchemaVersion
	CredentialPolicyName = shared.CredentialPolicyName
	CredentialEvidence   = shared.CredentialEvidence
	UnknownCredentialID  = shared.UnknownCredentialID

	CapabilitySupported   = shared.CapabilitySupported
	CapabilityLimited     = shared.CapabilityLimited
	CapabilityUnsupported = shared.CapabilityUnsupported
	CapabilityError       = shared.CapabilityError

	CompletenessComplete   = shared.CompletenessComplete
	CompletenessPartial    = shared.CompletenessPartial
	CompletenessIncomplete = shared.CompletenessIncomplete

	LineageVerified = shared.LineageVerified
	LineageInferred = shared.LineageInferred
	LineageUnknown  = shared.LineageUnknown

	AgentModeActive      = shared.AgentModeActive
	AgentModeDegraded    = shared.AgentModeDegraded
	AgentModeUnsupported = shared.AgentModeUnsupported
	AgentModeError       = shared.AgentModeError

	HealthStarting = shared.HealthStarting
	HealthHealthy  = shared.HealthHealthy
	HealthDegraded = shared.HealthDegraded
	HealthError    = shared.HealthError
)

type (
	Platform               = shared.Platform
	CapabilityState        = shared.CapabilityState
	Capability             = shared.Capability
	CapabilityReport       = shared.CapabilityReport
	Completeness           = shared.Completeness
	LineageConfidence      = shared.LineageConfidence
	Process                = shared.Process
	ExecutionObservation   = shared.ExecutionObservation
	FileObservation        = shared.FileObservation
	NetworkObservation     = shared.NetworkObservation
	UserNamespace          = shared.UserNamespace
	ExecPrivileges         = shared.ExecPrivileges
	CredentialCapabilities = shared.CredentialCapabilities
	CredentialSnapshot     = shared.CredentialSnapshot
	CredentialObservation  = shared.CredentialObservation
	Event                  = shared.Event
	RiskFactor             = shared.RiskFactor
	Finding                = shared.Finding
	AgentMode              = shared.AgentMode
	Health                 = shared.Health
	AgentStatus            = shared.AgentStatus
	CollectorHealth        = shared.CollectorHealth
)
