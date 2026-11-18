package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"xe-antishell/internal/model"
)

func TestRuleListIncludesPolicyAndSensorEvidence(t *testing.T) {
	verified := time.Date(2026, 1, 10, 9, 12, 0, 0, time.UTC)
	catalog := model.RuleCatalog{PolicySource: "managed", PolicyRevision: 3, Collector: "tetragon-json", Rules: []model.RuleStatus{{
		ID: "test-rule", Version: "1.0", Title: "규칙", Profile: "base", Enabled: true, Response: "observe",
		Sensors: []model.RuleSensor{{Name: "observation.test", State: "active", VerifiedAt: &verified}},
	}, {
		ID: "disabled-rule", Enabled: false, Reason: "프로필 꺼짐", Sensors: []model.RuleSensor{{Name: "observation.other", State: "unverified"}},
	}}}
	var out bytes.Buffer
	if err := writeRules(&out, catalog); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	for _, expected := range []string{"managed (revision 3)", "tetragon-json", "규칙", "test-rule", "1.0", "observe", "true", "observation.test=active@2026-01-10T09:12:00Z"} {
		if !strings.Contains(out.String(), expected) {
			t.Errorf("missing %q: %s", expected, out.String())
		}
	}
	last := lines[len(lines)-1]
	if !strings.Contains(last, "false") || !strings.Contains(last, "프로필 꺼짐") || !strings.Contains(last, "observation.other=unverified") || strings.Contains(last, "@") {
		t.Errorf("disabled rule: %s", last)
	}
}
