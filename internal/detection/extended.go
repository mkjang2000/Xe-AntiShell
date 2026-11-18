package detection

import (
	"xe-antishell/internal/identity"
	"xe-antishell/internal/model"
)

const extendedRuleVersion = "0.3.0"

func (e *Engine) evaluateExtended(event model.Event, lineage AncestorProvider) []model.Finding {
	origin, matched := e.MatchWebOrigin(event, lineage)
	if !matched {
		return nil
	}
	signals := e.classify(event, origin)
	root := event.Process.EUID == 0 && fieldAvailable(event, "process.euid")
	ruleID, summary := extendedRule(signals, root)
	if ruleID == "" {
		return nil
	}
	factors, score := extendedRisk(event, signals, root)
	severity := "medium"
	if signals.shell || score >= 70 {
		severity = "high"
	}
	if signals.shell && root {
		severity = "critical"
	}
	confidence := 0.55
	switch event.Process.LineageConfidence {
	case model.LineageVerified:
		confidence = 0.95
	case model.LineageInferred:
		confidence = 0.75
	}
	return []model.Finding{{
		ID:     identity.FindingID(ruleID, extendedRuleVersion, event.ID),
		RuleID: ruleID, RuleVersion: extendedRuleVersion, CreatedAt: event.EventTime,
		Severity: severity, Confidence: confidence, State: "open", Summary: summary,
		ProcessKey: event.Process.Key, EvidenceEventIDs: []string{event.ID},
		Source: "local", OriginService: origin,
		RiskScore: score, RiskFactors: factors, DetectionOnly: true,
	}}
}

// One observation event has one primary rule; its contributions remain visible.
func extendedRule(signals processSignals, root bool) (string, string) {
	switch {
	case signals.shell && root:
		return ruleWebDescendantRootShell, "웹 출처에서 root 셸 실행 관측. 행위 확인 필요."
	case signals.shell:
		return ruleWebDescendantShell, "웹 출처에서 셸 실행 관측. 행위 확인 필요."
	case signals.temporary:
		return ruleWebDescendantTemporaryExecutable, "웹 출처에서 임시 또는 메모리 경로의 실행 파일 실행 관측. 행위 확인 필요."
	case signals.connection:
		return ruleWebDescendantConnectionTool, "웹 출처에서 연결 도구 실행 관측. 실제 연결 여부와 행위 확인 필요."
	case signals.inline:
		return ruleWebDescendantInlineInterpreter, "웹 출처에서 인터프리터의 인라인 코드 실행 옵션 관측. 행위 확인 필요."
	case signals.script:
		return ruleWebDescendantTemporaryScript, "웹 출처에서 임시·메모리·파일 디스크립터 경로의 스크립트 실행 인자 관측. 실제 실행 여부와 행위 확인 필요."
	case signals.download:
		return ruleWebDescendantDownloadTool, "웹 출처에서 다운로드 도구 실행 관측. 전송 여부와 행위 확인 필요."
	case signals.recon:
		return ruleWebDescendantReconTool, "웹 출처에서 시스템 진단 도구 실행 관측. 행위 확인 필요."
	default:
		return "", ""
	}
}

// Contribution values describe policy weights, not probabilities. The total is
// bounded to 100; metadata contains only fixed observation identifiers.
func extendedRisk(event model.Event, signals processSignals, root bool) ([]model.RiskFactor, int) {
	factors := []model.RiskFactor{{ID: "web_origin", Score: 25}}
	for _, contribution := range []struct {
		observed bool
		id       string
		score    int
	}{
		{signals.shell, "shell_execution", 60},
		{signals.download, "download_tool", 35},
		{signals.recon, "recon_tool", 20},
		{signals.connection, "connection_tool", 45},
		{signals.inline, "inline_interpreter", 45},
		{signals.script, "temporary_script", 35},
		{signals.temporary, "temporary_executable", 40},
		{root, "root_identity", 10},
		{fieldAvailable(event, "process.cwd") && temporaryPath(event.Process.CWD, true), "temporary_working_directory", 5},
	} {
		if contribution.observed && len(factors) < 8 {
			factors = append(factors, model.RiskFactor{ID: contribution.id, Score: contribution.score})
		}
	}
	score := 0
	for _, factor := range factors {
		score += factor.Score
	}
	if score > 100 {
		score = 100
	}
	return factors, score
}
