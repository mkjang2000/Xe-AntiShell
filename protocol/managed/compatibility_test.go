package managed

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// These fixtures were captured from internal/managed before module extraction.
// This public seed is deterministic test data and must never be used in service.
func compatibilitySigningKey() ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func readCompatibilityGolden(t *testing.T, filename string) []byte {
	t.Helper()
	body, err := os.ReadFile("testdata/" + filename)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.TrimSpace(body)
}

func TestPolicySignedJSONMatchesPreExtractionGolden(t *testing.T) {
	now := time.Date(2026, 11, 16, 3, 0, 0, 0, time.UTC)
	private := compatibilitySigningKey()
	trusted := map[string]ed25519.PublicKey{"fixture-key": private.Public().(ed25519.PublicKey)}
	for _, test := range []struct {
		filename string
		extended bool
	}{
		{"policy-v1-legacy.json", false},
		{"policy-v1-extended.json", true},
	} {
		t.Run(test.filename, func(t *testing.T) {
			golden := readCompatibilityGolden(t, test.filename)
			decoded, err := DecodeSignedPolicy(golden)
			if err != nil {
				t.Fatal(err)
			}
			policy, err := VerifyPolicy(decoded, trusted, "agent-a", "enrollment-a", 7, now)
			if err != nil || policy.Detection.ExtendedProcessRules != test.extended {
				t.Fatalf("pre-extraction policy rejected or changed: %#v, %v", policy, err)
			}
			policy = DefaultPolicy("agent-a", "enrollment-a", 7, now)
			policy.Detection.ExtendedProcessRules = test.extended
			signed, err := SignPolicy(policy, "fixture-key", private)
			if err != nil {
				t.Fatal(err)
			}
			body, err := json.Marshal(signed)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(body, golden) {
				t.Fatalf("signed policy bytes changed:\nwant: %s\ngot:  %s", golden, body)
			}
		})
	}
}

func TestRemovalSignedJSONMatchesPreExtractionGolden(t *testing.T) {
	now := time.Date(2026, 11, 16, 3, 0, 0, 0, time.UTC)
	private := compatibilitySigningKey()
	trusted := map[string]ed25519.PublicKey{"fixture-key": private.Public().(ed25519.PublicKey)}
	challengeBytes := make([]byte, 32)
	for i := range challengeBytes {
		challengeBytes[i] = byte(i + 32)
	}
	challenge := base64.RawURLEncoding.EncodeToString(challengeBytes)
	golden := readCompatibilityGolden(t, "removal-v1.json")
	var decoded SignedRemovalGrant
	if err := DecodeStrict(golden, 16<<10, &decoded); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRemovalGrant(decoded, trusted, "agent-a", "enrollment-a", challenge, now); err != nil {
		t.Fatalf("pre-extraction removal grant rejected: %v", err)
	}
	grant := RemovalGrant{
		ID: "grant-1", AgentID: "agent-a", EnrollmentID: "enrollment-a",
		Challenge: challenge, Action: "uninstall", IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute),
	}
	signed, err := SignRemovalGrant(grant, "fixture-key", private)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, golden) {
		t.Fatalf("signed removal bytes changed:\nwant: %s\ngot:  %s", golden, body)
	}
}
