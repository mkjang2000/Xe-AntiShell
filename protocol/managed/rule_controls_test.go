package managed

import (
	"encoding/json"
	"testing"
	"time"
)

func TestSignedServiceRuleControls(t *testing.T) {
	now := time.Now().UTC()
	end := now.Add(time.Hour)
	p := DefaultPolicy("agent", "enroll", 1, now)
	trusted, key := testSigningKeys(t)
	valid := ServiceRuleControl{Service: "shop.service", RuleID: RuleWebDescendantShell, Mode: "suppress_until", Reason: "deployment", ExpiresAt: &end}
	p.Detection.ServiceRuleControls = []ServiceRuleControl{valid}
	sign, err := SignPolicy(p, "current", key)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(sign)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := DecodeSignedPolicy(body)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = VerifyPolicy(wire, trusted, "agent", "enroll", 1, now); err != nil {
		t.Fatal(err)
	}
	wire.Policy.Detection.ServiceRuleControls[0].Reason = "different"
	if _, err = VerifyPolicy(wire, trusted, "agent", "enroll", 1, now); err == nil {
		t.Fatal("modified exception remained valid")
	}
	for _, edit := range []func(*ServiceRuleControl){
		func(c *ServiceRuleControl) { c.Service = "*" }, func(c *ServiceRuleControl) { c.Service = "unknown" }, func(c *ServiceRuleControl) { c.RuleID = "future" }, func(c *ServiceRuleControl) { c.Mode = "always_allow" },
		func(c *ServiceRuleControl) { c.Reason = "" }, func(c *ServiceRuleControl) { c.Reason = "two\nlines" }, func(c *ServiceRuleControl) { c.ExpiresAt = nil }, func(c *ServiceRuleControl) { c.Mode = "disabled" }, func(c *ServiceRuleControl) { v := end.In(time.FixedZone("other", 3600)); c.ExpiresAt = &v },
	} {
		c := valid
		edit(&c)
		p.Detection.ServiceRuleControls = []ServiceRuleControl{c}
		if p.Validate() == nil {
			t.Fatalf("invalid control accepted: %+v", c)
		}
	}
	for _, v := range [][]ServiceRuleControl{{valid, valid}, make([]ServiceRuleControl, 257)} {
		if ValidateServiceRuleControls(v) == nil {
			t.Fatal("invalid list accepted")
		}
	}
	if valid.Allows(end.Add(-time.Nanosecond)) || !valid.Allows(end) {
		t.Fatal("expiry boundary")
	}
}
