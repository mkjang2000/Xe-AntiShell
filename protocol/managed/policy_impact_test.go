package managed

import (
	"strings"
	"testing"
	"time"
)

func TestPolicyImpactReportBindsAggregateCountsToInput(t *testing.T) {
	at := time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)
	input := PolicyImpactInput{
		TrialID: "trial-1", EvaluatedAt: at,
		Current:   DefaultPolicy("agent-a", "enrollment-a", 7, at),
		Candidate: DefaultPolicy("agent-a", "enrollment-a", 8, at),
	}
	digest, err := input.Digest()
	if err != nil {
		t.Fatal(err)
	}
	report := PolicyImpactReport{InputDigest: digest, SampleDigest: strings.Repeat("a", 64), HostDigest: strings.Repeat("b", 64), EvaluatedAt: at, Events: 2}
	for _, id := range builtinRuleIDs {
		report.Rules = append(report.Rules, PolicyRuleImpact{ID: id})
	}
	r := &report.Rules[0]
	r.HasInput, r.Current, r.Candidate, r.Removed = true, 2, 1, 1
	if err := report.ValidateFor(input); err != nil {
		t.Fatal(err)
	}
	r.Changed = 2
	if report.ValidateFor(input) == nil {
		t.Fatal("accepted more changes than findings shared by both policies")
	}
	r.Changed = 0
	input.Candidate.Detection.ExtendedProcessRules = !input.Candidate.Detection.ExtendedProcessRules
	if report.ValidateFor(input) == nil {
		t.Fatal("accepted comparison for different policy contents")
	}
}
