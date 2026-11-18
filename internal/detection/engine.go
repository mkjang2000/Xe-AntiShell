// Package detection evaluates bounded local rules against normalized events.
package detection

import (
	"fmt"
	"path/filepath"
	"strings"

	"xe-antishell/internal/config"
	"xe-antishell/internal/identity"
	"xe-antishell/internal/model"
)

type AncestorProvider interface {
	Ancestors(processKey string, maxDepth int) []model.Process
	CurrentByPID(pid int) (model.Process, bool)
}

type Engine struct {
	serviceObservations  map[string]config.ServiceObservationPolicy
	webExecutables       map[string]struct{}
	webServices          map[string]struct{}
	shells               map[string]struct{}
	allowedPairs         map[string]struct{}
	maxDepth             int
	extendedProcessRules bool
	privilegeRules       bool
	rootExecAlerts       string
}

// Options configures an immutable detector snapshot. ExtendedProcessRules is
// opt-in so existing local and signed policies retain their shell-only behavior.
type Options struct {
	ServiceObservations  []config.ServiceObservationPolicy
	WebExecutables       []string
	WebServices          []string
	Shells               []string
	AllowedPairs         []string
	ExtendedProcessRules bool
	PrivilegeRules       bool
	RootExecAlerts       string
}

// NewWithOptions preserves executable service aliases used by NewWithServices.
func NewWithOptions(options Options) *Engine {
	engine := NewWithServices(options.WebExecutables, options.WebServices, options.Shells, options.AllowedPairs)
	engine.serviceObservations = compileServiceObservations(options)
	engine.extendedProcessRules = options.ExtendedProcessRules
	engine.privilegeRules = options.PrivilegeRules
	engine.rootExecAlerts = options.RootExecAlerts
	return engine
}

// New creates the built-in rule engine. allowedPairs uses the explicit
// "web-executable:shell" form. The variadic shape keeps callers that do not
// need exceptions concise while allowing one configured list.
func New(webProcesses, shells []string, allowed ...[]string) *Engine {
	// Historically OriginService was compared with webProcesses. Keep those
	// values as service aliases for callers using the original constructor.
	return newEngine(webProcesses, webProcesses, shells, allowed...)
}

// NewWithServices creates an engine with explicit executable and service
// origins. Service names are exact, case-insensitive matches such as
// "orders-api.service". Executable values remain service aliases for backward
// compatibility with configurations created before web_services existed.
func NewWithServices(webExecutables, webServices, shells []string, allowed ...[]string) *Engine {
	services := append([]string(nil), webServices...)
	services = append(services, webExecutables...)
	return newEngine(webExecutables, services, shells, allowed...)
}

func newEngine(webExecutables, webServices, shells []string, allowed ...[]string) *Engine {
	var pairs []string
	if len(allowed) != 0 {
		pairs = allowed[0]
	}
	return &Engine{
		webExecutables: normalizedSet(webExecutables),
		webServices:    normalizedSet(webServices),
		shells:         normalizedSet(shells),
		allowedPairs:   normalizedSet(pairs),
		maxDepth:       64,
	}
}

func normalizedSet(values []string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value != "" {
			result[value] = struct{}{}
		}
	}
	return result
}

func processName(process model.Process) string {
	name := filepath.Base(process.Exe)
	if name == "." || name == string(filepath.Separator) {
		return ""
	}
	return strings.ToLower(name)
}

func (e *Engine) Evaluate(event model.Event, lineage AncestorProvider) []model.Finding {
	if event.Type == "file.write" || event.Type == "network.connect" {
		return e.evaluateServiceObservation(event)
	}
	findings := e.evaluateWeb(event, lineage)
	// Existing web findings already report this execution; retain one primary
	// finding instead of duplicating the same root exec in the global profile.
	if len(findings) > 0 && event.Type == "process.exec" {
		return findings
	}
	return append(findings, e.evaluatePrivilege(event, lineage)...)
}

func (e *Engine) evaluateWeb(event model.Event, lineage AncestorProvider) []model.Finding {
	if event.Type == "process.exec_observation" && e.extendedProcessRules {
		return e.evaluateExtended(event, lineage)
	}
	if event.Type != "process.exec" {
		return nil
	}
	if e.extendedProcessRules {
		return e.evaluateExtended(event, lineage)
	}
	if _, shell := e.shells[processName(event.Process)]; !shell {
		return nil
	}

	origin, matched := e.MatchWebOrigin(event, lineage)
	if !matched {
		return nil
	}
	if _, allowed := e.allowedPairs[origin+":"+processName(event.Process)]; allowed {
		return nil
	}

	severity := "high"
	ruleID := ruleWebDescendantShell
	summary := fmt.Sprintf("shell %s descended from web process %s", processName(event.Process), origin)
	if event.Process.EUID == 0 {
		severity = "critical"
		ruleID = ruleWebDescendantRootShell
		summary = fmt.Sprintf("root shell %s descended from web process %s", processName(event.Process), origin)
	}
	confidence := 0.55
	switch event.Process.LineageConfidence {
	case model.LineageVerified:
		confidence = 0.95
	case model.LineageInferred:
		confidence = 0.75
	}

	return []model.Finding{{
		ID:               identity.FindingID(ruleID, baseRuleVersion, event.ID),
		RuleID:           ruleID,
		RuleVersion:      baseRuleVersion,
		CreatedAt:        event.EventTime,
		Severity:         severity,
		Confidence:       confidence,
		State:            "open",
		Summary:          summary,
		ProcessKey:       event.Process.Key,
		EvidenceEventIDs: []string{event.ID},
		Source:           "local",
		OriginService:    origin,
	}}
}

// MatchWebOrigin reports the configured web origin for an event without
// applying shell or allowed-pair policy. It works both before and after the
// event has been added to lineage: pre-observation callers fall back to the
// current PPID and its ancestors. This lets audit ingestion discard unrelated
// shell events without retaining them in the in-memory process graph.
func (e *Engine) MatchWebOrigin(event model.Event, lineage AncestorProvider) (string, bool) {
	if origin, matched := e.matchServiceOrigin(event.Process); matched {
		return origin, true
	}

	ancestors := lineage.Ancestors(event.Process.Key, e.maxDepth)
	if len(ancestors) == 0 && event.Process.ParentKey == "" && event.Process.PPID > 0 {
		if parent, ok := lineage.CurrentByPID(event.Process.PPID); ok {
			ancestors = append(ancestors, parent)
			if e.maxDepth > 1 {
				ancestors = append(ancestors, lineage.Ancestors(parent.Key, e.maxDepth-1)...)
			}
		}
	}
	for _, ancestor := range ancestors {
		if origin, matched := e.matchProcessOrigin(ancestor); matched {
			return origin, true
		}
	}
	return "", false
}

func (e *Engine) matchProcessOrigin(process model.Process) (string, bool) {
	if origin, matched := e.matchServiceOrigin(process); matched {
		return origin, true
	}
	name := processName(process)
	if _, web := e.webExecutables[name]; web {
		return name, true
	}
	return "", false
}

func (e *Engine) matchServiceOrigin(process model.Process) (string, bool) {
	service := strings.ToLower(process.OriginService)
	if _, web := e.webServices[service]; web {
		return service, true
	}
	return "", false
}
