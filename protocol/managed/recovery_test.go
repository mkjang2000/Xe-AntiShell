package managed

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestRemovalGrantBindsHostEnrollmentActionAndChallenge(t *testing.T) {
	trusted, private := testSigningKeys(t)
	now := time.Now().UTC()
	challenge, err := NewChallenge()
	if err != nil {
		t.Fatal(err)
	}
	grant := RemovalGrant{ID: "grant-1", AgentID: "agent-a", EnrollmentID: "enrollment-a", Challenge: challenge, Action: "uninstall", IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
	signed, err := SignRemovalGrant(grant, "current", private)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRemovalGrant(signed, trusted, "agent-a", "enrollment-a", challenge, now); err != nil {
		t.Fatal(err)
	}
	if err := verifyValue("policy", signed.KeyID, signed.Grant, signed.Signature, trusted, MaxPolicyBytes); err == nil {
		t.Fatal("removal signature was accepted in policy domain")
	}
	for _, test := range []struct {
		name, agent, enrollment, challenge string
		when                               time.Time
	}{
		{"wrong host", "agent-b", "enrollment-a", challenge, now},
		{"old enrollment", "agent-a", "old", challenge, now},
		{"wrong operation", "agent-a", "enrollment-a", "different", now},
		{"expired", "agent-a", "enrollment-a", challenge, now.Add(5 * time.Minute)},
		{"future", "agent-a", "enrollment-a", challenge, now.Add(-2 * time.Minute)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := VerifyRemovalGrant(signed, trusted, test.agent, test.enrollment, test.challenge, test.when); err == nil {
				t.Fatal("invalid grant accepted")
			}
		})
	}
	tampered := signed
	tampered.Grant.Action = "disable_agent"
	if _, err := VerifyRemovalGrant(tampered, trusted, "agent-a", "enrollment-a", challenge, now); err == nil {
		t.Fatal("tampered grant accepted")
	}
	grant.Action = "run_command"
	if _, err := SignRemovalGrant(grant, "current", private); err == nil {
		t.Fatal("arbitrary action granted")
	}
	grant.Action = "uninstall"
	grant.ExpiresAt = now.Add(time.Hour)
	if _, err := SignRemovalGrant(grant, "current", private); err == nil {
		t.Fatal("unbounded grant lifetime accepted")
	}
}

func TestRecoveryVerifierContainsNoOriginalCodeAndIsEnrollmentScoped(t *testing.T) {
	code, verifier, err := GenerateRecoveryCode("agent-a", "enrollment-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(code) < 40 {
		t.Fatal("recovery code entropy unexpectedly short")
	}
	if !VerifyRecoveryCode(verifier, "agent-a", "enrollment-a", code) {
		t.Fatal("correct recovery code rejected")
	}
	for _, test := range []struct{ agent, enrollment, code string }{
		{"agent-b", "enrollment-a", code},
		{"agent-a", "enrollment-b", code},
		{"agent-a", "enrollment-a", "short"},
		{"agent-a", "enrollment-a", strings.Repeat("A", 43)},
	} {
		if VerifyRecoveryCode(verifier, test.agent, test.enrollment, test.code) {
			t.Fatal("invalid recovery context/code accepted")
		}
	}
	body, err := json.Marshal(verifier)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), code) {
		t.Fatal("recovery verifier contains plaintext code")
	}
	otherCode, other, err := GenerateRecoveryCode("agent-a", "enrollment-a")
	if err != nil {
		t.Fatal(err)
	}
	if otherCode == code || other.Digest == verifier.Digest || other.ID == verifier.ID {
		t.Fatal("per-code identities were reused")
	}
	verifier.ID = other.ID
	if VerifyRecoveryCode(verifier, "agent-a", "enrollment-a", code) {
		t.Fatal("tampered verifier identity accepted")
	}
}

func TestPrecreatedRecoveryCodeBindsOnlyAfterEnrollment(t *testing.T) {
	code, err := NewChallenge()
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewRecoveryVerifier("agent-a", "enrollment-a", code)
	if err != nil || !VerifyRecoveryCode(verifier, "agent-a", "enrollment-a", code) {
		t.Fatalf("precreated code was not bound: %v", err)
	}
	for _, invalid := range []string{"", "password", code + " ", code[:len(code)-1]} {
		if _, err := NewRecoveryVerifier("agent-a", "enrollment-a", invalid); err == nil {
			t.Fatal("accepted invalid or noncanonical recovery material")
		}
	}
}
