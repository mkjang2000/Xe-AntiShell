package detection

import (
	"slices"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"

	"xe-antishell/internal/config"
	"xe-antishell/internal/identity"
	"xe-antishell/internal/model"
)

const (
	operationRuleVersion                = "1.0.0"
	ruleServiceProtectedFileWrite       = managed.RuleServiceProtectedFileWrite
	ruleServiceUnexpectedTCPDestination = managed.RuleServiceUnexpectedTCPDestination
)

var operationIdentityFields = [...]string{
	"source", "event_type", "event_id", "boot_id", "event_time",
	"process.key", "process.exec_id", "process.pid", "process.start_time", "process.origin_service",
}

// Explicit service membership avoids matching executable aliases or another
// systemd unit whose spelling differs only by case.
func compileServiceObservations(opts Options) map[string]config.ServiceObservationPolicy {
	if len(opts.ServiceObservations) == 0 {
		return nil
	}
	scopes := make(map[string]config.ServiceObservationPolicy)
	for _, scope := range opts.ServiceObservations {
		if !slices.Contains(opts.WebServices, scope.Service) {
			continue
		}
		scope.ProtectedDirs = slices.Clone(scope.ProtectedDirs)
		scope.AllowedWriteDirs = slices.Clone(scope.AllowedWriteDirs)
		scope.AllowedTCPDestinations = slices.Clone(scope.AllowedTCPDestinations)
		for i := range scope.AllowedTCPDestinations {
			scope.AllowedTCPDestinations[i].Ports = slices.Clone(scope.AllowedTCPDestinations[i].Ports)
		}
		scopes[scope.Service] = scope
	}
	return scopes
}

func (e *Engine) evaluateServiceObservation(event model.Event) []model.Finding {
	p := event.Process
	scope, ok := e.serviceObservations[p.OriginService]
	if !ok || event.ID == "" || event.BootID == "" || event.EventTime.IsZero() || p.Key == "" || p.ExecID == "" || p.PID <= 0 || p.StartTime.IsZero() {
		return nil
	}
	switch event.Type {
	case "file.write":
		return evaluateProtectedFileWrite(event, scope.ProtectedDirs, scope.AllowedWriteDirs)
	case "network.connect":
		return evaluateTCPDestination(event, scope.AllowedTCPDestinations)
	}
	return nil
}

func operationFinding(event model.Event, ruleID, summary, factor string, score int) []model.Finding {
	// Only candidates need the full provenance check. Other observations have
	// already been excluded by their service, path, destination or outcome.
	for _, field := range operationIdentityFields {
		if !evidenceFieldAvailable(event, field) {
			return nil
		}
	}
	severity := "medium"
	if score >= 70 {
		severity = "high"
	}
	confidence := 0.55
	switch event.Process.LineageConfidence {
	case model.LineageVerified:
		confidence = 0.95
	case model.LineageInferred:
		confidence = 0.75
	}
	return []model.Finding{{
		ID: identity.FindingID(ruleID, operationRuleVersion, event.ID), RuleID: ruleID, RuleVersion: operationRuleVersion,
		CreatedAt: event.EventTime, Severity: severity, Confidence: confidence, State: "open", Summary: summary,
		ProcessKey: event.Process.Key, EvidenceEventIDs: []string{event.ID}, Source: "local", OriginService: event.Process.OriginService,
		RiskScore: score, RiskFactors: []model.RiskFactor{{ID: factor, Score: score}}, DetectionOnly: true,
	}}
}
