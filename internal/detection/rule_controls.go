package detection

import (
	"sort"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"xe-antishell/internal/model"
)

func compileRuleControls(list []managed.ServiceRuleControl) map[string]map[string]managed.ServiceRuleControl {
	var byService map[string]map[string]managed.ServiceRuleControl
	if len(list) > 0 {
		byService = make(map[string]map[string]managed.ServiceRuleControl)
	}
	for _, c := range list {
		if c.ExpiresAt != nil {
			at := *c.ExpiresAt
			c.ExpiresAt = &at
		}
		if byService[c.Service] == nil {
			byService[c.Service] = make(map[string]managed.ServiceRuleControl)
		}
		byService[c.Service][c.RuleID] = c
	}
	return byService
}

type ruleDecision struct {
	at       time.Time
	controls map[string]managed.ServiceRuleControl
}

func (r ruleDecision) allows(id string) bool {
	c, ok := r.controls[id]
	return !ok || c.Allows(r.at)
}

// Each existing detector produces at most one primary finding.
func (r ruleDecision) filter(findings []model.Finding) []model.Finding {
	if len(findings) > 0 && !r.allows(findings[0].RuleID) {
		return nil
	}
	return findings
}

func (e *Engine) ruleControlStatuses(at time.Time) map[string][]model.ServiceRuleStatus {
	if len(e.ruleControls) == 0 {
		return nil
	}
	byID := make(map[string][]model.ServiceRuleStatus)
	for _, controls := range e.ruleControls {
		for _, c := range controls {
			if c.ExpiresAt != nil {
				expires := *c.ExpiresAt
				c.ExpiresAt = &expires
			}
			byID[c.RuleID] = append(byID[c.RuleID], model.ServiceRuleStatus{ServiceRuleControl: c, Suppressed: !c.Allows(at)})
		}
	}
	for _, entries := range byID {
		sort.Slice(entries, func(i, j int) bool { return entries[i].Service < entries[j].Service })
	}
	return byID
}
