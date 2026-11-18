package detection

import (
	"path/filepath"
	"strings"

	"xe-antishell/internal/identity"
	"xe-antishell/internal/model"
)

const privilegeRuleVersion = "0.4.0"

// PrivilegeEnabled reports the immutable opt-in profile, independently of any
// surrounding service-level detection.enabled gate.
func (e *Engine) PrivilegeEnabled() bool { return e.privilegeRules }

// IsPrivilegeCandidate widens evidence retention, never response authority.
// A failed/partial credential operation can still be retained as observation;
// evaluateCredentials separately requires a complete applied transition.
func (e *Engine) IsPrivilegeCandidate(event model.Event) bool {
	if !e.privilegeRules {
		return false
	}
	if event.Type == "process.credential_change" {
		return event.Source == "tetragon" && event.Credential != nil && event.Credential.Validate() == nil && event.Process.PID == event.Credential.TGID && (event.Process.TID == 0 || event.Process.TID == event.Credential.TID)
	}
	return validRootExecution(event)
}

func validRootExecution(event model.Event) bool {
	return event.Type == "process.exec" && event.Process.EUID == 0 &&
		filepath.IsAbs(event.Process.Exe) && privilegeFieldAvailable(event, "process.euid") && privilegeFieldAvailable(event, "process.exe")
}

// A quality marker on an object or descendant invalidates its proof. The one
// advisory scope marker does not hide a complete credential pair whose namespace
// is explicitly unknown; it never makes an unknown namespace into host proof.
func privilegeFieldAvailable(event model.Event, field string) bool {
	if field == "credential" && unresolvedCredentialNamespaceScope(event.Credential) {
		return evidenceFieldAvailableExcept(event, field, "credential.user_namespace_scope")
	}
	return evidenceFieldAvailable(event, field)
}

func evidenceFieldAvailable(event model.Event, field string) bool {
	return evidenceFieldAvailableExcept(event, field, "")
}

// A marker names either the required field, an enclosing object, or one
// of its children. Sibling names with the same textual prefix are unrelated.
func evidenceFieldAvailableExcept(event model.Event, field, ignoreMissing string) bool {
	for group, fields := range [][]string{event.MissingFields, event.TruncatedFields, event.RedactedFields} {
		for _, missing := range fields {
			if group == 0 && ignoreMissing != "" && missing == ignoreMissing {
				continue
			}
			short, long := field, missing
			if len(missing) < len(field) {
				short, long = missing, field
			}
			if strings.HasPrefix(long, short) && (len(short) == len(long) || long[len(short)] == '.' || long[len(short)] == '[') {
				return false
			}
		}
	}
	return true
}

func (e *Engine) evaluatePrivilege(event model.Event, lineage AncestorProvider, r ruleDecision) []model.Finding {
	if !e.privilegeRules {
		return nil
	}
	switch event.Type {
	case "process.exec":
		return e.evaluateRootExecution(event, lineage)
	case "process.credential_change":
		return e.evaluateCredentials(event, lineage, r)
	default:
		return nil
	}
}

func (e *Engine) evaluateRootExecution(event model.Event, lineage AncestorProvider) []model.Finding {
	if !validRootExecution(event) {
		return nil
	}
	factors := []model.RiskFactor{{ID: "root_execution", Score: 25}}
	webOrigin, web := e.privilegeWebOrigin(event, lineage)
	if web {
		factors = append(factors, model.RiskFactor{ID: "web_origin", Score: 35})
	}
	if temporaryPath(event.Process.Exe, false) {
		factors = append(factors, model.RiskFactor{ID: "temporary_executable", Score: 35})
	}
	if nonrootParentSnapshot(event, lineage) {
		factors = append(factors, model.RiskFactor{ID: "nonroot_parent_snapshot", Score: 20})
	}
	if properties := event.Process.ExecPrivileges; privilegedExecMetadata(properties) && privilegeFieldAvailable(event, "process.exec_privileges") {
		factors = append(factors, model.RiskFactor{ID: "privileged_exec_metadata", Score: 20})
	}
	if _, shell := e.shells[processName(event.Process)]; shell && event.Process.OriginService == "" && !web {
		factors = append(factors, model.RiskFactor{ID: "unattributed_shell", Score: 20})
	}
	score := privilegeScore(factors)
	if e.rootExecAlerts != "all" && score < 45 {
		return nil
	}
	scope := "unknown"
	if event.Process.Credentials != nil && event.Process.Credentials.Validate() == nil && privilegeFieldAvailable(event, "process.credentials.user_namespace") {
		scope = event.Process.Credentials.UserNamespace.Scope()
	}
	summary := "root(EUID 0) 실행 관측. 승인된 작업인지 확인."
	switch scope {
	case "host":
		summary = "초기 user namespace의 EUID 0 실행 관측. 승인된 작업인지 확인."
	case "non_host":
		summary = "비호스트 user namespace의 EUID 0 실행 관측. 컨테이너와 승인된 작업 범위를 확인."
	default:
		summary = "EUID 0 실행 관측(user namespace 미확인). 승인된 작업인지 확인."
	}
	origin := event.Process.OriginService
	if web {
		origin = webOrigin
	}
	return privilegeFinding(event, rulePrivilegeRootExecution, summary, factors, origin, executionConfidence(event))
}

// Parent credentials are source snapshots, not proof that the parent currently
// runs as that user or that the child gained privileges through an exploit.
func nonrootParentSnapshot(event model.Event, lineage AncestorProvider) bool {
	if !privilegeFieldAvailable(event, "ancestors") || !privilegeFieldAvailable(event, "process.parent_identity") || !privilegeFieldAvailable(event, "process.parent_key") {
		return false
	}
	var parent model.Process
	found := false
	if event.Process.ParentKey != "" {
		ancestors := lineage.Ancestors(event.Process.Key, 1)
		if len(ancestors) > 0 && ancestors[0].Key == event.Process.ParentKey {
			parent, found = ancestors[0], true
		}
		if !found {
			for _, candidate := range event.Ancestors {
				if candidate.Key == event.Process.ParentKey {
					parent, found = candidate, true
					break
				}
			}
		}
	}
	if !found {
		return false
	}
	return parent.EUID > 0 && parent.EUID < int64(^uint32(0))
}

func executionConfidence(event model.Event) float64 {
	switch event.Process.LineageConfidence {
	case model.LineageVerified:
		return .95
	case model.LineageInferred:
		return .75
	default:
		return .55
	}
}

func privilegeScore(factors []model.RiskFactor) int {
	score := 0
	for _, factor := range factors {
		score += factor.Score
	}
	if score > 100 {
		return 100
	}
	return score
}

func privilegeFinding(event model.Event, rule, summary string, factors []model.RiskFactor, origin string, confidence float64) []model.Finding {
	score := privilegeScore(factors)
	severity := "low"
	if score >= 70 {
		severity = "high"
	} else if score >= 40 {
		severity = "medium"
	}
	return []model.Finding{{ID: identity.FindingID(rule, privilegeRuleVersion, event.ID), RuleID: rule, RuleVersion: privilegeRuleVersion,
		CreatedAt: event.EventTime, Severity: severity, Confidence: confidence, State: "open", Summary: summary, ProcessKey: event.Process.Key,
		EvidenceEventIDs: []string{event.ID}, Source: "local", OriginService: origin, RiskScore: score, RiskFactors: factors, DetectionOnly: true}}
}

func privilegedExecMetadata(properties *model.ExecPrivileges) bool {
	if properties == nil || len(properties.Reasons) > 3 {
		return false
	}
	if properties.SetUID != nil && *properties.SetUID == ^uint32(0) || properties.SetGID != nil && *properties.SetGID == ^uint32(0) {
		return false
	}
	seen := map[string]bool{}
	for _, reason := range properties.Reasons {
		switch reason {
		case "PRIVILEGES_RAISED_EXEC_FILE_CAP", "PRIVILEGES_RAISED_EXEC_FILE_SETUID", "PRIVILEGES_RAISED_EXEC_FILE_SETGID":
		default:
			return false
		}
		if seen[reason] {
			return false
		}
		seen[reason] = true
	}
	return properties.SetUID != nil || properties.SetGID != nil || len(properties.Reasons) > 0
}

func (e *Engine) privilegeWebOrigin(event model.Event, lineage AncestorProvider) (string, bool) {
	if !privilegeFieldAvailable(event, "process.origin_service") {
		event.Process.OriginService = ""
	}
	if origin, matched := e.matchServiceOrigin(event.Process); matched {
		return origin, true
	}
	if !privilegeFieldAvailable(event, "ancestors") || !privilegeFieldAvailable(event, "process.parent_identity") || !privilegeFieldAvailable(event, "process.parent_key") {
		return "", false
	}
	return e.MatchWebOrigin(event, lineage)
}
