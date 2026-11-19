package agent

import (
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"

	"xe-antishell/internal/capability"
	"xe-antishell/internal/collector"
	"xe-antishell/internal/detection"
	"xe-antishell/internal/model"
	"xe-antishell/internal/response"
)

const serviceObservationCapability = "detection.service_observations"

// Evidence is scoped to the selected source and subscription. Refreshing passive
// prerequisites cannot fabricate receipt of a live source event.
type sourceRuntimeEvidence struct {
	ExecAt        time.Time
	LineageAt     time.Time
	FileAt        time.Time
	NetworkAt     time.Time
	InterpreterAt time.Time
	CredentialAt  time.Time
}

func (s *Service) recordRuntimeEvent(event model.Event, generation uint64) {
	if (event.Type != "process.exec" && !isOperationEvent(event.Type)) || event.Process.PID < 1 || event.Process.Exe == "" || (event.Source != "audit" && event.Source != "tetragon") {
		return
	}
	if isOperationEvent(event.Type) && validateOperationEvent(event) != nil {
		return
	}
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	if event.Source == "tetragon" && generation != s.recovery.generation {
		return
	}
	if s.runtimeEvidence == nil {
		s.runtimeEvidence = make(map[string]sourceRuntimeEvidence)
	}
	evidence := s.runtimeEvidence[event.Source]
	now := time.Now().UTC()
	switch event.Type {
	case "process.credential_change":
		if event.Credential != nil && event.Credential.Outcome == "applied" {
			// Use the original source/ingress clock, not delayed queue processing.
			// An old receipt must never activate a newly loaded policy generation.
			at := event.EventTime
			if event.IngestTime.Before(at) {
				at = event.IngestTime
			}
			if !at.IsZero() && !event.IngestTime.IsZero() && !at.After(now) && at.After(evidence.CredentialAt) {
				evidence.CredentialAt = at
			}
		}
	case "file.write":
		evidence.FileAt = now
	case "network.connect":
		evidence.NetworkAt = now
	case "process.exec_observation":
		if detection.ValidExecutionEvidence(event) {
			evidence.InterpreterAt = now
		}
	case "process.exec":
		evidence.ExecAt = now
		if detection.ValidExecutionEvidence(event) {
			evidence.InterpreterAt = now
		}
	}
	if event.Type == "process.exec" && event.Process.ParentKey != "" && (event.Process.LineageConfidence == model.LineageVerified || (event.Source == "audit" && event.Process.LineageConfidence == model.LineageInferred)) {
		evidence.LineageAt = evidence.ExecAt
	}
	s.runtimeEvidence[event.Source] = evidence
}

func (s *Service) runtimeSnapshot() (model.AgentStatus, model.CapabilityReport) {
	return s.runtimeSnapshotFor(s.detectionState.Load())
}

func (s *Service) runtimeSnapshotFor(policy *detectionState) (model.AgentStatus, model.CapabilityReport) {
	s.statusMu.RLock()
	status := s.operationStatus(s.status)
	report := cloneCapabilityReport(s.report)
	evidence := s.runtimeEvidence[sourceForCollector(status.Collector)]
	recovery := s.recovery
	stream := s.collectorHealthSnapshot()
	s.statusMu.RUnlock()
	if status.LastEventAt != nil {
		at := *status.LastEventAt
		status.LastEventAt = &at
	}
	status.CollectorHealth = stream
	if status.Collector == "tetragon-json" && status.Mode == model.AgentModeActive {
		if stream != nil && stream.LastError != "" {
			status.Health = model.HealthError
			status.LastError = stream.LastError
		} else if evidence.ExecAt.IsZero() && status.Health == model.HealthHealthy {
			status.Health = model.HealthStarting
		}
	}
	applyRuntimeCapabilities(&report, status, evidence, stream)
	if status.Collector == "tetragon-json" {
		recovery.addDetails(&report)
	}
	if report.Capabilities == nil {
		report.Capabilities = make(map[string]model.Capability)
	}
	addFileIntegrityCapability(&report)
	report.Capabilities[response.CapabilityName] = response.Capability(s.config.Response.AllowTerminate)
	report.Capabilities[serviceObservationCapability] = model.Capability{
		Name: serviceObservationCapability, Provider: "local-detector", State: model.CapabilitySupported,
		Implementation: "implemented", RuntimeState: "available", Reason: "서비스별 파일·TCP 서명 정책 지원",
		RuntimeReason: "파일·TCP 센서의 최근 수신은 해당 관측 항목에 표시됩니다.",
		Details:       map[string]string{"contract": "1", "scope_source": policy.serviceObservationSource()},
	}
	report.Capabilities["detection.service_rule_controls"] = model.Capability{
		Name: "detection.service_rule_controls", Provider: "local-detector", State: model.CapabilitySupported, Implementation: "implemented", RuntimeState: "available",
		Reason: "서비스별 규칙·만료 예외 지원", Details: map[string]string{"contract": "1"},
	}
	if s.supportsApplicationPolicies() {
		report.Capabilities[managed.ApplicationPoliciesCapability] = model.Capability{
			Name: managed.ApplicationPoliciesCapability, Provider: "local-detector", State: model.CapabilitySupported,
			Implementation: "implemented", RuntimeState: "available", Reason: "직접 확인한 시스템 서비스별 서명 정책 지원",
			Details: map[string]string{"contract": "1"},
		}
	}
	s.applyPrivilegeCapabilities(&status, &report, evidence, policy.privilegeEnabled())
	status.CapabilityReport = &report
	return status, report
}

func sourceForCollector(name string) string {
	switch name {
	case "audit-dispatcher":
		return "audit"
	case "tetragon-json":
		return "tetragon"
	default:
		return ""
	}
}

func (s *Service) collectorHealthSnapshot() *model.CollectorHealth {
	s.collectorMu.Lock()
	selected := s.collector
	s.collectorMu.Unlock()
	if selected == nil {
		return nil
	}
	return collectorHealth(selected.Health())
}

func collectorHealth(value collector.HealthSnapshot) *model.CollectorHealth {
	health := &model.CollectorHealth{
		Name: value.Name, Running: value.Running,
		EventsReceived: value.EventsReceived, EventsEmitted: value.EventsEmitted,
		EventsSkipped: value.EventsDropped, ParseErrors: value.ParseErrors,
		LastError: value.LastError,
	}
	if !value.LastEventAt.IsZero() {
		at := value.LastEventAt
		health.LastEventAt = &at
	}
	return health
}

func applyRuntimeCapabilities(report *model.CapabilityReport, status model.AgentStatus, evidence sourceRuntimeEvidence, stream *model.CollectorHealth) {
	for name, value := range report.Capabilities {
		value.Implementation = "implemented"
		value.RuntimeState = "inactive"
		value.RuntimeReason = "host prerequisite is unavailable"
		switch value.State {
		case model.CapabilitySupported:
			value.RuntimeState = "available"
			value.RuntimeReason = "host prerequisite detected; this is not proof of active monitoring"
		case model.CapabilityLimited:
			value.RuntimeState = "unverified"
			value.RuntimeReason = "passive checks only; runtime operation has not been verified"
		case model.CapabilityError:
			value.RuntimeState = "error"
			value.RuntimeReason = "host prerequisite probe failed"
		}
		switch name {
		case capability.IMACapability, capability.TPMCapability:
			value.Implementation = "planned"
			value.RuntimeState = "inactive"
			value.RuntimeReason = "host prerequisite probe only; agent integrity verification is not implemented"
		case capability.CredentialCapability, capability.FileCapability, capability.NetworkCapability, capability.InterpreterCapability:
			value.RuntimeState = "unverified"
			value.RuntimeReason = "awaiting a verified source event from the current collector subscription"
			if status.Collector != "tetragon-json" && (name != capability.InterpreterCapability || status.Collector != "audit-dispatcher") {
				value.RuntimeState = "inactive"
				value.RuntimeReason = "a compatible source is not selected for this observation"
			}
		case capability.AuditCapability, capability.TetragonCapability:
			value.RuntimeState = "inactive"
			value.RuntimeReason = "not the selected process collector"
		case capability.ProcessExecCapability, capability.ProcessLineageCapability:
			value.RuntimeState = "inactive"
			value.RuntimeReason = "no live process collector is selected"
		}
		report.Capabilities[name] = value
	}

	source := sourceForCollector(status.Collector)
	if source == "" {
		return
	}
	collectorName := capability.AuditCapability
	if source == "tetragon" {
		collectorName = capability.TetragonCapability
	}
	setRuntime(report, collectorName, "unverified", "collector selected; awaiting a real process execution event", time.Time{})
	setRuntime(report, capability.ProcessExecCapability, "unverified", "waiting for process execution evidence from the selected collector", time.Time{})
	setRuntime(report, capability.ProcessLineageCapability, "unverified", "waiting for an execution event with source or derived ancestry", time.Time{})
	if !evidence.ExecAt.IsZero() {
		collectorReason := "live Tetragon process execution events received"
		execReason := "kernel process execution stream received; durable evidence may be limited by candidate filters"
		if source == "audit" {
			collectorReason = "live audit execution events received through the dispatcher; full rule coverage remains unverified"
			execReason = "audit execution events received; candidate filters apply and audit provides no process-exit stream"
		}
		setRuntime(report, collectorName, "active", collectorReason, evidence.ExecAt)
		setRuntime(report, capability.ProcessExecCapability, "active", execReason, evidence.ExecAt)
		if source == "tetragon" {
			setRuntime(report, capability.EBPFCapability, "active", "live Tetragon execution evidence confirms process eBPF hooks are attached", evidence.ExecAt)
		}
	}
	if !evidence.LineageAt.IsZero() {
		reason := "Tetragon source ancestry received; missing parents remain explicit"
		if source == "audit" {
			reason = "derived ancestry observed from audit and live process context; no process-exit stream"
		}
		setRuntime(report, capability.ProcessLineageCapability, "active", reason, evidence.LineageAt)
	}
	if source == "tetragon" {
		for _, item := range []struct {
			name   string
			at     time.Time
			reason string
		}{
			{capability.CredentialCapability, evidence.CredentialAt, "same-hook before/after credential pair and successful return received; source trust remains required"},
			{capability.FileCapability, evidence.FileAt, "vfs_write events received; positive returns confirm bytes written; writev, mmap and io_uring are outside this hook"},
			{capability.NetworkCapability, evidence.NetworkAt, "TCP connect attempts received; a zero return is initiation, not an established connection; UDP and socket contents are not observed"},
			{capability.InterpreterCapability, evidence.InterpreterAt, "fixed interpreter invocation argument policy matches received; code execution completion is not established"},
		} {
			if !item.at.IsZero() {
				setRuntime(report, item.name, "active", item.reason, item.at)
			}
		}
	} else if !evidence.InterpreterAt.IsZero() {
		setRuntime(report, capability.InterpreterCapability, "active", "exact audit argv yielded interpreter invocation metadata; code contents are omitted", evidence.InterpreterAt)
	}
	if status.Health == model.HealthError || (status.LastError != "" && status.Mode != model.AgentModeActive) || (stream != nil && stream.LastError != "") {
		for _, name := range []string{collectorName, capability.ProcessExecCapability, capability.ProcessLineageCapability, capability.CredentialCapability, capability.FileCapability, capability.NetworkCapability, capability.InterpreterCapability} {
			setRuntime(report, name, "error", "selected collector or agent reported a runtime failure; inspect system status", time.Time{})
		}
		if source == "tetragon" {
			setRuntime(report, capability.EBPFCapability, "unverified", "source operation failed; active attachment is no longer established by this agent", time.Time{})
		}
		return
	}
	if stream != nil && !stream.Running {
		for _, name := range []string{collectorName, capability.ProcessExecCapability, capability.ProcessLineageCapability, capability.CredentialCapability, capability.FileCapability, capability.NetworkCapability, capability.InterpreterCapability} {
			setRuntime(report, name, "unverified", "selected collector stream is not running", time.Time{})
		}
		if source == "tetragon" {
			setRuntime(report, capability.EBPFCapability, "unverified", "selected collector stream is not running", time.Time{})
		}
	}
}

func setRuntime(report *model.CapabilityReport, name, state, reason string, verified time.Time) {
	value, ok := report.Capabilities[name]
	if !ok {
		value = model.Capability{Name: name, State: model.CapabilityLimited, Provider: "runtime", Reason: "passive prerequisite was not reported", Implementation: "implemented"}
	}
	value.RuntimeState = state
	value.RuntimeReason = reason
	value.VerifiedAt = nil
	if !verified.IsZero() {
		at := verified
		value.VerifiedAt = &at
	}
	report.Capabilities[name] = value
}

func cloneCapabilityReport(source model.CapabilityReport) model.CapabilityReport {
	clone := source
	clone.Capabilities = make(map[string]model.Capability, len(source.Capabilities))
	for name, value := range source.Capabilities {
		if value.Details != nil {
			details := make(map[string]string, len(value.Details))
			for key, detail := range value.Details {
				details[key] = detail
			}
			value.Details = details
		}
		if value.VerifiedAt != nil {
			at := *value.VerifiedAt
			value.VerifiedAt = &at
		}
		clone.Capabilities[name] = value
	}
	return clone
}
