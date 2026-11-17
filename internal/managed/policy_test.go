package managed

import (
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
			p := DefaultPolicy("agent", "enroll", 1, now)
			test.mutate(&p)
			if p.Validate() == nil {
				t.Fatal("unsafe policy accepted")
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
