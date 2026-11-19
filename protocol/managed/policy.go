package managed

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
)

type Policy struct {
	SchemaVersion string           `json:"schema_version"`
	ID            string           `json:"policy_id"`
	Revision      uint64           `json:"revision"`
	AgentID       string           `json:"agent_id"`
	EnrollmentID  string           `json:"enrollment_id"`
	IssuedAt      time.Time        `json:"issued_at"`
	ExpiresAt     time.Time        `json:"expires_at"`
	Detection     DetectionPolicy  `json:"detection"`
	Response      ResponsePolicy   `json:"response"`
	UninstallMode string           `json:"uninstall_mode"`
	Monitoring    MonitoringPolicy `json:"monitoring"`

	Applications []ApplicationPolicy `json:"applications,omitempty"`
}

// DetectionPolicy omits a false ExtendedProcessRules value to preserve the signed
// bytes of policies issued before extended process rules were introduced.
type DetectionPolicy struct {
	Enabled              bool                 `json:"enabled"`
	ExtendedProcessRules bool                 `json:"extended_process_rules,omitempty" yaml:"extended_process_rules,omitempty"`
	PrivilegeRules       bool                 `json:"privilege_rules,omitempty" yaml:"privilege_rules,omitempty"`
	RootExecAlerts       string               `json:"root_exec_alerts,omitempty" yaml:"root_exec_alerts,omitempty"`
	WebExecutables       []string             `json:"web_executables"`
	WebServices          []string             `json:"web_services"`
	Shells               []string             `json:"shells"`
	AllowedPairs         []string             `json:"allowed_pairs"`
	ServiceRuleControls  []ServiceRuleControl `json:"service_rule_controls,omitempty" yaml:"service_rule_controls,omitempty"`
	// Omitted inherits the host configuration. A present list replaces it in full.
	ServiceObservations *[]ServiceObservationPolicy `json:"service_observations,omitempty" yaml:"service_observations,omitempty"`
}

type ResponsePolicy struct {
	Mode                 string   `json:"mode"`
	Action               string   `json:"action"`
	RiskThreshold        int      `json:"risk_threshold"`
	MinConfidence        float64  `json:"min_confidence"`
	RequiredCapabilities []string `json:"required_capabilities"`
}

type MonitoringPolicy struct {
	Enabled               bool `json:"enabled"`
	SampleIntervalSeconds int  `json:"sample_interval_seconds"`
	ProcessLimit          int  `json:"process_limit"`
}

type SignedPolicy struct {
	Policy    Policy `json:"policy"`
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"`
}

func (p Policy) Validate() error {
	if p.SchemaVersion != SchemaVersion || !validIdentifier(p.ID, 128) || !validIdentifier(p.AgentID, 128) || !validIdentifier(p.EnrollmentID, 160) || p.Revision < 1 || p.Revision > math.MaxInt64 {
		return errors.New("invalid policy version or identity")
	}
	if p.IssuedAt.IsZero() || p.ExpiresAt.IsZero() || !p.ExpiresAt.After(p.IssuedAt) || p.ExpiresAt.Sub(p.IssuedAt) > 366*24*time.Hour {
		return errors.New("invalid policy validity interval")
	}
	if err := validateDetectionAndResponse(p.Detection, p.Response); err != nil {
		return err
	}
	switch p.UninstallMode {
	case "allow", "approval_required", "deny":
	default:
		return errors.New("unsupported uninstall mode")
	}
	if p.Monitoring.SampleIntervalSeconds < 5 || p.Monitoring.SampleIntervalSeconds > 3600 || p.Monitoring.ProcessLimit < 1 || p.Monitoring.ProcessLimit > 2000 {
		return errors.New("monitoring limits are outside allowed bounds")
	}
	return validateApplications(p.Applications, p.Response.Mode)
}

func validateDetectionAndResponse(d DetectionPolicy, r ResponsePolicy) error {
	if d.RootExecAlerts != "" && (!d.PrivilegeRules || (d.RootExecAlerts != "suspicious" && d.RootExecAlerts != "all")) {
		return errors.New("invalid privilege root execution alert mode")
	}
	if err := validateValues(d.WebExecutables, 256, true); err != nil {
		return fmt.Errorf("web executables: %w", err)
	}
	if err := validateValues(d.Shells, 64, true); err != nil {
		return fmt.Errorf("shells: %w", err)
	}
	if err := validateValues(d.WebServices, 1024, false); err != nil {
		return fmt.Errorf("web services: %w", err)
	}
	if err := validateSignedServiceObservations(d.ServiceObservations); err != nil {
		return err
	}
	if err := ValidateServiceRuleControls(d.ServiceRuleControls); err != nil {
		return err
	}
	if len(d.AllowedPairs) > 512 {
		return errors.New("too many detection exceptions")
	}
	seen := map[string]struct{}{}
	for _, pair := range d.AllowedPairs {
		parts := strings.Split(pair, ":")
		if len(parts) != 2 || !validName(parts[0], false) || !validName(parts[1], true) {
			return errors.New("invalid detection exception")
		}
		key := strings.ToLower(pair)
		if _, exists := seen[key]; exists {
			return errors.New("duplicate detection exception")
		}
		seen[key] = struct{}{}
	}
	if d.Enabled && !d.PrivilegeRules && (len(d.Shells) == 0 || len(d.WebExecutables)+len(d.WebServices) == 0) {
		return errors.New("enabled detection requires origins and shells")
	}
	switch r.Mode {
	case "observe", "would_block", "enforce":
	default:
		return errors.New("unsupported response mode")
	}
	switch r.Action {
	case "none", "terminate":
	default:
		return errors.New("unsupported response action")
	}
	if r.Mode == "enforce" && r.Action == "none" {
		return errors.New("enforcement requires an explicit action")
	}
	if r.RiskThreshold < 0 || r.RiskThreshold > 100 || math.IsNaN(r.MinConfidence) || math.IsInf(r.MinConfidence, 0) || r.MinConfidence < 0 || r.MinConfidence > 1 {
		return errors.New("invalid response threshold")
	}
	if err := validateValues(r.RequiredCapabilities, 32, false); err != nil {
		return fmt.Errorf("response capabilities: %w", err)
	}
	if r.Mode != "observe" && (r.Action != "terminate" || len(r.RequiredCapabilities) == 0 || r.RiskThreshold == 0 || r.MinConfidence == 0) {
		return errors.New("response requires an action, explicit capability gates, and nonzero thresholds")
	}
	if r.Mode != "observe" && !d.Enabled {
		return errors.New("response requires enabled detection")
	}
	return nil
}

func DefaultPolicy(agentID, enrollmentID string, revision uint64, now time.Time) Policy {
	return Policy{SchemaVersion: SchemaVersion, ID: "default", Revision: revision, AgentID: agentID, EnrollmentID: enrollmentID,
		IssuedAt: now.UTC(), ExpiresAt: now.Add(24 * time.Hour).UTC(),
		Detection:     DetectionPolicy{Enabled: true, WebExecutables: []string{"httpd", "apache2", "nginx", "php-fpm", "gunicorn", "uwsgi"}, Shells: []string{"sh", "bash", "dash", "zsh", "ksh", "ash", "busybox", "fish", "csh", "tcsh"}},
		Response:      ResponsePolicy{Mode: "observe", Action: "none", RiskThreshold: 90, MinConfidence: .95},
		UninstallMode: "approval_required", Monitoring: MonitoringPolicy{Enabled: true, SampleIntervalSeconds: 10, ProcessLimit: 200}}
}

func SignPolicy(policy Policy, keyID string, private ed25519.PrivateKey) (SignedPolicy, error) {
	if err := policy.Validate(); err != nil {
		return SignedPolicy{}, err
	}
	signature, err := signValue("policy", keyID, policy, private, MaxPolicyBytes)
	if err != nil {
		return SignedPolicy{}, err
	}
	signed := SignedPolicy{Policy: policy, KeyID: keyID, Signature: signature}
	if err = signed.validateWireSize(); err != nil {
		return SignedPolicy{}, err
	}
	return signed, nil
}

// The size limit on the transport includes the key ID and signature envelope.
func (s SignedPolicy) validateWireSize() error {
	body, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if len(body) > MaxPolicyBytes {
		return errors.New("signed policy exceeds its wire size limit")
	}
	return nil
}

func VerifyPolicy(signed SignedPolicy, trusted map[string]ed25519.PublicKey, agentID, enrollmentID string, minimumRevision uint64, now time.Time) (Policy, error) {
	if err := signed.validateWireSize(); err != nil {
		return Policy{}, err
	}
	if err := verifyValue("policy", signed.KeyID, signed.Policy, signed.Signature, trusted, MaxPolicyBytes); err != nil {
		return Policy{}, err
	}
	policy := signed.Policy
	if err := policy.Validate(); err != nil {
		return Policy{}, err
	}
	if policy.AgentID != agentID || policy.EnrollmentID != enrollmentID {
		return Policy{}, errors.New("policy target does not match this enrollment")
	}
	if policy.Revision < minimumRevision {
		return Policy{}, errors.New("policy revision rollback rejected")
	}
	if policy.IssuedAt.After(now.Add(time.Minute)) || !now.Before(policy.ExpiresAt) {
		return Policy{}, errors.New("policy is expired or not yet valid")
	}
	return policy, nil
}

func DecodeSignedPolicy(data []byte) (SignedPolicy, error) {
	var policy SignedPolicy
	if err := DecodeStrict(data, MaxPolicyBytes, &policy); err != nil {
		return SignedPolicy{}, err
	}
	return policy, nil
}

func validateValues(values []string, maximum int, basename bool) error {
	if len(values) > maximum {
		return errors.New("too many values")
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !validName(value, basename) {
			return errors.New("invalid name")
		}
		key := strings.ToLower(value)
		if _, exists := seen[key]; exists {
			return errors.New("duplicate name")
		}
		seen[key] = struct{}{}
	}
	return nil
}

func validName(value string, basename bool) bool {
	if value == "" || len(value) > 255 || value != strings.TrimSpace(value) || value == "." || value == ".." {
		return false
	}
	for _, char := range value {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '-' || char == '_' || char == '.' || (!basename && (char == '@' || char == '\\'))) {
			return false
		}
	}
	return true
}
