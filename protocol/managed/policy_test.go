package managed

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"
)

func testSigningKeys(t *testing.T) (map[string]ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	return map[string]ed25519.PublicKey{"current": public}, private
}

func TestPolicySignatureRejectsChangesTargetsAndRollback(t *testing.T) {
	trusted, private := testSigningKeys(t)
	now := time.Date(2026, 11, 16, 3, 0, 0, 0, time.UTC)
	policy := DefaultPolicy("agent-a", "enrollment-a", 7, now)
	signed, err := SignPolicy(policy, "current", private)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := VerifyPolicy(signed, trusted, "agent-a", "enrollment-a", 7, now)
	if err != nil || decoded.Revision != 7 {
		t.Fatalf("verify valid policy: %#v %v", decoded, err)
	}
	for _, test := range []struct {
		name, agent, enrollment string
		revision                uint64
		when                    time.Time
	}{
		{"wrong agent", "agent-b", "enrollment-a", 7, now},
		{"old enrollment", "agent-a", "enrollment-b", 7, now},
		{"rollback", "agent-a", "enrollment-a", 8, now},
		{"expired", "agent-a", "enrollment-a", 7, now.Add(24 * time.Hour)},
		{"future", "agent-a", "enrollment-a", 7, now.Add(-2 * time.Minute)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := VerifyPolicy(signed, trusted, test.agent, test.enrollment, test.revision, test.when); err == nil {
				t.Fatal("invalid policy context was accepted")
			}
		})
	}
	tampered := signed
	tampered.Policy.UninstallMode = "allow"
	if _, err := VerifyPolicy(tampered, trusted, "agent-a", "enrollment-a", 7, now); err == nil {
		t.Fatal("tampered removal policy accepted")
	}
	tampered = signed
	tampered.KeyID = "other"
	if _, err := VerifyPolicy(tampered, trusted, "agent-a", "enrollment-a", 7, now); err == nil {
		t.Fatal("unknown signing key accepted")
	}
	trusted["other"] = trusted["current"]
	if _, err := VerifyPolicy(tampered, trusted, "agent-a", "enrollment-a", 7, now); err == nil {
		t.Fatal("changing key ID accepted even though key ID is signed")
	}
	if _, err := SignPolicy(policy, "current", nil); err == nil {
		t.Fatal("nil signing key accepted")
	}
}

func TestPolicyStrictSchemaAndRoundTrip(t *testing.T) {
	trusted, private := testSigningKeys(t)
	now := time.Now().UTC()
	signed, err := SignPolicy(DefaultPolicy("agent", "enrollment", 1, now), "current", private)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeSignedPolicy(body)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyPolicy(decoded, trusted, "agent", "enrollment", 1, now); err != nil {
		t.Fatal(err)
	}
	injected := strings.Replace(string(body), `"detection":{`, `"collector_command":"/bin/sh","detection":{`, 1)
	if _, err := DecodeSignedPolicy([]byte(injected)); err == nil {
		t.Fatal("privileged unsupported policy field was silently accepted")
	}
	if _, err := DecodeSignedPolicy(append(body, []byte(` {}`)...)); err == nil {
		t.Fatal("trailing policy accepted")
	}
	if _, err := DecodeSignedPolicy(make([]byte, MaxPolicyBytes+1)); err == nil {
		t.Fatal("oversized policy accepted")
	}
}

func TestPolicySignaturePreservesLegacyDetectionPayload(t *testing.T) {
	// These declarations preserve the pre-extension field order and JSON tags.
	type legacyDetectionPolicy struct {
		Enabled        bool     `json:"enabled"`
		WebExecutables []string `json:"web_executables"`
		WebServices    []string `json:"web_services"`
		Shells         []string `json:"shells"`
		AllowedPairs   []string `json:"allowed_pairs"`
	}
	type legacyPolicy struct {
		SchemaVersion string                `json:"schema_version"`
		ID            string                `json:"policy_id"`
		Revision      uint64                `json:"revision"`
		AgentID       string                `json:"agent_id"`
		EnrollmentID  string                `json:"enrollment_id"`
		IssuedAt      time.Time             `json:"issued_at"`
		ExpiresAt     time.Time             `json:"expires_at"`
		Detection     legacyDetectionPolicy `json:"detection"`
		Response      ResponsePolicy        `json:"response"`
		UninstallMode string                `json:"uninstall_mode"`
		Monitoring    MonitoringPolicy      `json:"monitoring"`
	}
	trusted, private := testSigningKeys(t)
	now := time.Date(2026, 11, 16, 3, 0, 0, 0, time.UTC)
	p := DefaultPolicy("agent", "enrollment", 1, now)
	if p.Detection.ExtendedProcessRules {
		t.Fatal("default signed policy must preserve original detection behavior")
	}
	legacy := legacyPolicy{
		SchemaVersion: p.SchemaVersion, ID: p.ID, Revision: p.Revision,
		AgentID: p.AgentID, EnrollmentID: p.EnrollmentID, IssuedAt: p.IssuedAt, ExpiresAt: p.ExpiresAt,
		Detection: legacyDetectionPolicy{p.Detection.Enabled, p.Detection.WebExecutables, p.Detection.WebServices, p.Detection.Shells, p.Detection.AllowedPairs},
		Response:  p.Response, UninstallMode: p.UninstallMode, Monitoring: p.Monitoring,
	}
	legacyBody, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := signValue("policy", "current", legacy, private, MaxPolicyBytes)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(struct {
		Policy    json.RawMessage `json:"policy"`
		KeyID     string          `json:"key_id"`
		Signature string          `json:"signature"`
	}{legacyBody, "current", signature})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := DecodeSignedPolicy(body)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := VerifyPolicy(signed, trusted, "agent", "enrollment", 1, now)
	if err != nil {
		t.Fatalf("pre-extension signature rejected: %v", err)
	}
	if decoded.Detection.ExtendedProcessRules {
		t.Fatal("legacy signed payload enabled extended process rules")
	}
	currentBody, err := json.Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(currentBody, legacyBody) {
		t.Fatalf("legacy signed bytes changed:\nold: %s\nnew: %s", legacyBody, currentBody)
	}
	signed.Policy.Detection.ExtendedProcessRules = true
	if _, err := VerifyPolicy(signed, trusted, "agent", "enrollment", 1, now); err == nil {
		t.Fatal("unsigned expansion of detection rules accepted")
	}
}

func TestPolicyExtendedProcessRulesRoundTrip(t *testing.T) {
	trusted, private := testSigningKeys(t)
	now := time.Now().UTC()
	p := DefaultPolicy("agent", "enrollment", 1, now)
	p.Detection.ExtendedProcessRules = true
	signed, err := SignPolicy(p, "current", private)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeSignedPolicy(body)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyPolicy(decoded, trusted, "agent", "enrollment", 1, now)
	if err != nil || !verified.Detection.ExtendedProcessRules {
		t.Fatalf("extended policy roundtrip: %#v %v", verified.Detection, err)
	}
	decoded.Policy.Detection.ExtendedProcessRules = false
	if _, err := VerifyPolicy(decoded, trusted, "agent", "enrollment", 1, now); err == nil {
		t.Fatal("tampered extended rule option accepted")
	}
}

func TestPolicyValidationRejectsUnboundedOrUnsafeInputs(t *testing.T) {
	now := time.Now().UTC()
	for _, test := range []struct {
		name   string
		mutate func(*Policy)
	}{
		{"unknown version", func(p *Policy) { p.SchemaVersion = "future" }},
		{"zero revision", func(p *Policy) { p.Revision = 0 }},
		{"no validity", func(p *Policy) { p.ExpiresAt = p.IssuedAt }},
		{"executable path", func(p *Policy) { p.Detection.WebExecutables = []string{"/usr/bin/node"} }},
		{"shell whitespace", func(p *Policy) { p.Detection.Shells = []string{" bash"} }},
		{"duplicate origin", func(p *Policy) { p.Detection.WebServices = []string{"orders.service", "Orders.Service"} }},
		{"no shell", func(p *Policy) { p.Detection.Shells = nil }},
		{"malformed exception", func(p *Policy) { p.Detection.AllowedPairs = []string{"orders.service:/bin/sh"} }},
		{"unknown action", func(p *Policy) { p.Response.Action = "run_command" }},
		{"unsafe enforcement", func(p *Policy) { p.Response.Mode = "enforce" }},
		{"missing capability gates", func(p *Policy) { p.Response.Mode = "would_block"; p.Response.Action = "terminate" }},
		{"NaN confidence", func(p *Policy) { p.Response.MinConfidence = math.NaN() }},
		{"monitoring flood", func(p *Policy) { p.Monitoring.SampleIntervalSeconds = 0 }},
		{"process flood", func(p *Policy) { p.Monitoring.ProcessLimit = 100000 }},
		{"unknown uninstall", func(p *Policy) { p.UninstallMode = "force" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, extended := range []bool{false, true} {
				p := DefaultPolicy("agent", "enroll", 1, now)
				p.Detection.ExtendedProcessRules = extended
				test.mutate(&p)
				if p.Validate() == nil {
					t.Fatalf("unsafe policy accepted with extended process rules = %t", extended)
				}
			}
		})
	}
}

func TestPublicKeyEncoding(t *testing.T) {
	trusted, _ := testSigningKeys(t)
	encoded := EncodePublicKey(trusted["current"])
	decoded, err := DecodePublicKey(encoded)
	if err != nil || !decoded.Equal(trusted["current"]) {
		t.Fatalf("publickey roundtrip: %v", err)
	}
	if _, err := DecodePublicKey("secret-or-invalid"); err == nil {
		t.Fatal("invalid key accepted")
	}
}

func TestPrivilegePolicyOptionalFieldsPreserveLegacyAndValidateMode(t *testing.T) {
	p := DefaultPolicy("agent-test", "enrollment-test", 1, time.Now().UTC())
	old, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(old, []byte("privilege_rules")) || bytes.Contains(old, []byte("root_exec_alerts")) {
		t.Fatal("default policy changed legacy signed bytes")
	}
	p.Detection.PrivilegeRules = true
	p.Detection.RootExecAlerts = "suspicious"
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	p.Detection.WebExecutables = nil
	p.Detection.WebServices = nil
	p.Detection.Shells = nil
	if err := p.Validate(); err != nil {
		t.Fatal("global-only privilege policy rejected", err)
	}
	p.Detection.RootExecAlerts = "all"
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	p.Detection.PrivilegeRules = false
	if p.Validate() == nil {
		t.Fatal("inactive privilege policy emitted new mode")
	}
	p.Detection.PrivilegeRules = true
	p.Detection.RootExecAlerts = "unbounded"
	if p.Validate() == nil {
		t.Fatal("unknown mode accepted")
	}
}
