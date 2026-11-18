package managed

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"time"
)

// PolicyImpactInput is the per-host projection exported by an authenticated
// central preview. It contains policy inputs, never a measurement sample.
type PolicyImpactInput struct {
	TrialID     string    `json:"trial_id"`
	EvaluatedAt time.Time `json:"evaluated_at"`
	Current     Policy    `json:"current"`
	Candidate   Policy    `json:"candidate"`
}

func (p PolicyImpactInput) Digest() (string, error) {
	if !validIdentifier(p.TrialID, 128) || p.EvaluatedAt.IsZero() || p.Current.AgentID != p.Candidate.AgentID || p.Current.EnrollmentID != p.Candidate.EnrollmentID || p.Current.Revision+1 != p.Candidate.Revision {
		return "", errors.New("invalid policy impact identity")
	}
	if err := p.Current.Validate(); err != nil {
		return "", err
	}
	if err := p.Candidate.Validate(); err != nil {
		return "", err
	}
	b, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	d := sha256.Sum256(b)
	return hex.EncodeToString(d[:]), nil
}

// The report has a closed schema. Aggregate counts can be audited by repeating
// the local comparison with the same sample, host configuration and policy input.
type PolicyImpactReport struct {
	InputDigest  string             `json:"input_sha256"`
	SampleDigest string             `json:"sample_sha256"`
	HostDigest   string             `json:"host_config_sha256"`
	EvaluatedAt  time.Time          `json:"evaluated_at"`
	Events       int                `json:"events"`
	Rules        []PolicyRuleImpact `json:"rules"`
}

type PolicyRuleImpact struct {
	ID        string `json:"id"`
	HasInput  bool   `json:"has_input_type"`
	Current   int    `json:"current"`
	Candidate int    `json:"candidate"`
	Added     int    `json:"added"`
	Removed   int    `json:"removed"`
	Changed   int    `json:"changed"`
}

func (p PolicyImpactReport) ValidateFor(input PolicyImpactInput) error {
	digest, err := input.Digest()
	if err != nil {
		return err
	}
	if p.InputDigest != digest || !p.EvaluatedAt.Equal(input.EvaluatedAt) || p.Events < 1 || p.Events > 5000 || len(p.Rules) != len(builtinRuleIDs) {
		return errors.New("report does not match the comparison input")
	}
	for _, hash := range []string{p.SampleDigest, p.HostDigest} {
		b, err := hex.DecodeString(hash)
		if err != nil || len(b) != sha256.Size || hash != hex.EncodeToString(b) {
			return errors.New("invalid comparison hash")
		}
	}
	seen := map[string]bool{}
	for _, r := range p.Rules {
		if !slices.Contains(builtinRuleIDs[:], r.ID) || seen[r.ID] || !r.validCounts(p.Events) {
			return errors.New("invalid per-rule comparison")
		}
		seen[r.ID] = true
	}
	return nil
}

func (r PolicyRuleImpact) validCounts(events int) bool {
	if r.Current < 0 || r.Current > events || r.Candidate < 0 || r.Candidate > events {
		return false
	}
	if r.Removed < 0 || r.Removed > r.Current || r.Added < 0 || r.Added > r.Candidate {
		return false
	}
	if !r.HasInput && (r.Current != 0 || r.Candidate != 0) {
		return false
	}
	common := r.Current - r.Removed
	return common == r.Candidate-r.Added && r.Changed >= 0 && r.Changed <= common
}
