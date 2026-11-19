package managed

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestApplicationPoliciesAreBoundInSignedEnvelope(t *testing.T) {
	key, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	policy := DefaultPolicy("server-a", "registered-a", 1, now)
	policy.Applications = []ApplicationPolicy{
		{
			Service: "nginx.service", PolicyID: "web-response", PolicyVersion: 3,
			Detection: DetectionPolicy{Enabled: true, WebServices: []string{"nginx.service"}, Shells: []string{"bash"}},
			Response:  ResponsePolicy{Mode: "enforce", Action: "terminate", RiskThreshold: 90, MinConfidence: .95, RequiredCapabilities: []string{"observation.process_exec"}},
		},
		{
			Service: "pm2-deploy.service", PolicyID: "deployment-observe", PolicyVersion: 2,
			Detection: DetectionPolicy{Enabled: true, WebServices: []string{"pm2-deploy.service"}, Shells: []string{"bash"}},
			Response:  policy.Response,
		},
	}
	signed, err := SignPolicy(policy, "central-key", private)
	if err != nil {
		t.Fatal(err)
	}
	trust := map[string]ed25519.PublicKey{"central-key": key}
	checked, err := VerifyPolicy(signed, trust, policy.AgentID, policy.EnrollmentID, 1, now)
	if err != nil || checked.Applications[0].Response.Mode != "enforce" || checked.Applications[1].Response.Mode != "observe" {
		t.Fatalf("unexpected verified application policy: %v", err)
	}
	signed.Policy.Applications[0].PolicyVersion++
	if _, err := VerifyPolicy(signed, trust, policy.AgentID, policy.EnrollmentID, 1, now); err == nil {
		t.Fatal("unsigned application policy version change was accepted")
	}
}

func TestApplicationPoliciesRejectAmbiguousOrUnscopedSettings(t *testing.T) {
	for name, change := range map[string]func(*Policy){
		"duplicate service":         func(p *Policy) { p.Applications = append(p.Applications, p.Applications[0]) },
		"wildcard":                  func(p *Policy) { p.Applications[0].Service = "web*.service" },
		"missing version":           func(p *Policy) { p.Applications[0].PolicyVersion = 0 },
		"another service as origin": func(p *Policy) { p.Applications[0].Detection.WebServices = []string{"other.service"} },
		"unscoped executable":       func(p *Policy) { p.Applications[0].Detection.WebExecutables = []string{"nginx"} },
		"global privileges":         func(p *Policy) { p.Applications[0].Detection.PrivilegeRules = true },
		"control of another service": func(p *Policy) {
			p.Applications[0].Detection.ServiceRuleControls = []ServiceRuleControl{{Service: "other.service", RuleID: RuleWebDescendantShell, Mode: "disabled"}}
		},
		"scope of another service": func(p *Policy) {
			p.Applications[0].Detection.ServiceObservations = &[]ServiceObservationPolicy{{Service: "other.service", ProtectedDirs: []string{"/srv/example"}}}
		},
		"fallback enforcement": func(p *Policy) {
			p.Response.Mode, p.Response.Action = "enforce", "terminate"
			p.Response.RequiredCapabilities = []string{"observation.process_exec"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			policy := DefaultPolicy("server-a", "registered-a", 1, time.Now())
			policy.Applications = []ApplicationPolicy{{
				Service: "nginx.service", PolicyID: "web-observe", PolicyVersion: 1,
				Detection: DetectionPolicy{Enabled: true, WebServices: []string{"nginx.service"}, Shells: []string{"bash"}},
				Response:  policy.Response,
			}}
			change(&policy)
			if err := policy.Validate(); err == nil {
				t.Fatal("invalid application policy accepted")
			}
		})
	}
}
