package managed

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func installationFixture(t *testing.T) (InstallationCode, time.Time) {
	t.Helper()
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Installation test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, private.Public(), private)
	if err != nil {
		t.Fatal(err)
	}
	return InstallationCode{
		Version: SchemaVersion, CentralURL: "https://central.example:9443", AgentID: "web-01",
		Token:     base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		CAPEM:     string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		ExpiresAt: now.Add(time.Hour),
	}, now
}

func TestInstallationCodeRoundtripAndExpiry(t *testing.T) {
	code, now := installationFixture(t)
	encoded, err := EncodeInstallationCode(code)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeInstallationCode(" \n"+encoded+"\n", now)
	if err != nil || decoded != code {
		t.Fatal("installation code did not roundtrip")
	}
	for _, at := range []time.Time{code.ExpiresAt, code.ExpiresAt.Add(time.Second)} {
		if decoded, err := DecodeInstallationCode(encoded, at); err == nil || decoded != (InstallationCode{}) {
			t.Fatal("expired code returned credential data")
		}
	}
	// Encoding is time-independent, including historical records and fixtures.
	code.ExpiresAt = now.Add(-time.Hour)
	if _, err := EncodeInstallationCode(code); err != nil {
		t.Fatal("encoder unexpectedly consulted the current clock")
	}
}

func TestValidateEnrollmentURL(t *testing.T) {
	for _, value := range []string{"https://central.example", "https://central.example:9443", "https://central.example/", "https://localhost:443", "https://192.0.2.1:9443", "https://[2001:db8::1]:9443"} {
		if err := ValidateEnrollmentURL(value); err != nil {
			t.Errorf("valid origin rejected: %s", value)
		}
	}
	for _, value := range []string{
		"", "http://central.example", "HTTPS://central.example", " https://central.example", "https://central.example\n",
		"https://user:pass@central.example", "https://central.example/enroll", "https://central.example//", "https://central.example/%2f",
		"https://central.example?", "https://central.example?x=1", "https://central.example#", "https://central.example#fragment",
		"https:///central.example", "https:central.example", "https://central.example:", "https://central.example:0", "https://central.example:65536",
		"https://central.example:0443", "https://central.example:abc", "https://[localhost]", "https://::1", "https://[fe80::1%25eth0]",
		"https://bad_host.example", "https://-host.example", "https://host..example", "https://host-.example", "https://" + strings.Repeat("a", 64) + ".example",
	} {
		if ValidateEnrollmentURL(value) == nil {
			t.Errorf("invalid origin accepted: %s", value)
		}
	}
}

func TestInstallationCodeRejectsInvalidFieldsWithoutEcho(t *testing.T) {
	valid, now := installationFixture(t)
	tests := []struct {
		name   string
		mutate func(*InstallationCode)
	}{
		{"version", func(c *InstallationCode) { c.Version = "secret-version" }},
		{"url", func(c *InstallationCode) { c.CentralURL = "https://user:secret-url@central.example" }},
		{"identity", func(c *InstallationCode) { c.AgentID = "secret agent" }},
		{"identity length", func(c *InstallationCode) { c.AgentID = strings.Repeat("a", 129) }},
		{"credential length", func(c *InstallationCode) { c.Token = "secret-token" }},
		{"credential padding", func(c *InstallationCode) { c.Token += "=" }},
		{"credential tail", func(c *InstallationCode) { c.Token = c.Token[:42] + "B" }},
		{"empty expiry", func(c *InstallationCode) { c.ExpiresAt = time.Time{} }},
		{"expiry year", func(c *InstallationCode) { c.ExpiresAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) }},
		{"empty CA", func(c *InstallationCode) { c.CAPEM = "" }},
		{"invalid CA", func(c *InstallationCode) { c.CAPEM = "secret-ca" }},
		{"CA preamble", func(c *InstallationCode) { c.CAPEM = "secret-preamble\n" + c.CAPEM }},
		{"CA trailing data", func(c *InstallationCode) { c.CAPEM += "secret-tail" }},
		{"CA count", func(c *InstallationCode) { c.CAPEM = strings.Repeat(c.CAPEM, 9) }},
		{"CA bound", func(c *InstallationCode) { c.CAPEM = strings.Repeat("x", MaxInstallationCodeBytes+1) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			code := valid
			test.mutate(&code)
			if encoded, err := EncodeInstallationCode(code); err == nil || encoded != "" {
				t.Fatal("invalid structure was encoded")
			}
			body, err := json.Marshal(code)
			if err != nil {
				return
			}
			input := installationCodePrefix + base64.RawURLEncoding.EncodeToString(body)
			decoded, err := DecodeInstallationCode(input, now)
			if err == nil || decoded != (InstallationCode{}) {
				t.Fatal("invalid code returned credentials")
			}
			if strings.Contains(err.Error(), "secret-") || strings.Contains(err.Error(), valid.Token) || strings.Contains(err.Error(), input) {
				t.Fatal("error disclosed code contents")
			}
		})
	}
}

func TestInstallationCodeRejectsMalformedAndAmbiguousEncoding(t *testing.T) {
	code, now := installationFixture(t)
	encoded, err := EncodeInstallationCode(code)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(code)
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{"", "xeas2.secret", "xeas1.secret!", encoded + "=", strings.Repeat("x", MaxInstallationCodeBytes+1)} {
		if _, err := DecodeInstallationCode(input, now); err == nil {
			t.Fatal("invalid encoded input accepted")
		}
	}
	for _, invalid := range []string{
		"null", "[]", string(body) + "{}", strings.Replace(string(body), `"version":"1"`, `"version":"1","version":"1"`, 1),
		strings.Replace(string(body), `"version":"1"`, `"version":"1","Version":"1"`, 1),
		strings.TrimSuffix(string(body), "}") + `,"secret-property":"secret-value"}`,
		strings.Replace(string(body), `"expires_at":"2030-01-02T04:04:05Z"`, `"expires_at":"secret-date"`, 1),
	} {
		input := installationCodePrefix + base64.RawURLEncoding.EncodeToString([]byte(invalid))
		if _, err := DecodeInstallationCode(input, now); err == nil || strings.Contains(err.Error(), "secret-") {
			t.Fatal("ambiguous or malformed JSON accepted or disclosed")
		}
	}
}

func TestInstallationCodeChecksCAValidityAndLeafRejection(t *testing.T) {
	code, now := installationFixture(t)
	encoded, err := EncodeInstallationCode(code)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeInstallationCode(encoded, now.Add(-2*time.Hour)); err == nil {
		t.Fatal("not-yet-valid CA accepted")
	}
	code.ExpiresAt = now.Add(48 * time.Hour)
	encoded, err = EncodeInstallationCode(code)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeInstallationCode(encoded, now.Add(25*time.Hour)); err == nil {
		t.Fatal("expired CA accepted")
	}
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, private.Public(), private)
	if err != nil {
		t.Fatal(err)
	}
	code.CAPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	if _, err := EncodeInstallationCode(code); err == nil {
		t.Fatal("non-CA certificate accepted as installation trust")
	}
}
