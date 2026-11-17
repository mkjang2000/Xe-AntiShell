package managed

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const MaxInstallationCodeBytes = 16 << 10

const installationCodePrefix = "xeas1."

// InstallationCode carries the initial pinned trust through an authenticated
// operator channel. It contains a secret and must never be logged or published.
// It is not signed; authenticity comes from that trusted delivery channel.
type InstallationCode struct {
	Version    string    `json:"version"`
	CentralURL string    `json:"central_url"`
	AgentID    string    `json:"agent_id"`
	Token      string    `json:"token"`
	CAPEM      string    `json:"ca_pem"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// EncodeInstallationCode validates structure without consulting the clock.
// The issuer owns token lifetime; DecodeInstallationCode checks expiry on use.
func EncodeInstallationCode(code InstallationCode) (string, error) {
	if err := validateInstallationCode(code, nil); err != nil {
		return "", err
	}
	body, err := json.Marshal(code)
	if err != nil {
		return "", errors.New("invalid installation code encoding")
	}
	encoded := installationCodePrefix + base64.RawURLEncoding.EncodeToString(body)
	if len(encoded) > MaxInstallationCodeBytes {
		return "", errors.New("installation code exceeds its size limit")
	}
	return encoded, nil
}

// DecodeInstallationCode rejects invalid, ambiguous and expired input before
// callers send any credential. Errors never contain supplied field values.
func DecodeInstallationCode(input string, now time.Time) (InstallationCode, error) {
	if len(input) == 0 || len(input) > MaxInstallationCodeBytes {
		return InstallationCode{}, errors.New("installation code is empty or exceeds its size limit")
	}
	input = strings.TrimSpace(input)
	if !strings.HasPrefix(input, installationCodePrefix) {
		return InstallationCode{}, errors.New("unsupported installation code format")
	}
	encoded := strings.TrimPrefix(input, installationCodePrefix)
	body, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(body) != encoded {
		return InstallationCode{}, errors.New("invalid installation code encoding")
	}
	var code InstallationCode
	if !uniqueInstallationFields(body) || DecodeStrict(body, MaxInstallationCodeBytes, &code) != nil {
		return InstallationCode{}, errors.New("invalid installation code data")
	}
	if err := validateInstallationCode(code, &now); err != nil {
		return InstallationCode{}, err
	}
	return code, nil
}

// ValidateEnrollmentURL accepts an HTTPS origin with an optional trailing slash.
// It deliberately rejects endpoint paths and noncanonical host/port syntax.
func ValidateEnrollmentURL(raw string) error {
	invalid := errors.New("central enrollment URL must be an HTTPS origin")
	u, err := url.Parse(raw)
	if err != nil || !strings.HasPrefix(raw, "https://") || raw != strings.TrimSpace(raw) || strings.ContainsAny(raw, "?#%\\") || u.Scheme != "https" || u.Opaque != "" || u.User != nil || u.Hostname() == "" || (u.Path != "" && u.Path != "/") || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return invalid
	}
	hostname := u.Hostname()
	if net.ParseIP(hostname) == nil {
		if strings.ContainsAny(u.Host, "[]") || !validEnrollmentHostname(hostname) {
			return invalid
		}
	} else if strings.Contains(hostname, ":") && !strings.HasPrefix(u.Host, "[") {
		return invalid
	}
	if strings.HasSuffix(u.Host, ":") {
		return invalid
	}
	if port := u.Port(); port != "" {
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 || strconv.Itoa(number) != port {
			return invalid
		}
	}
	return nil
}

func validEnrollmentHostname(hostname string) bool {
	hostname = strings.TrimSuffix(hostname, ".")
	if len(hostname) == 0 || len(hostname) > 253 {
		return false
	}
	for _, label := range strings.Split(hostname, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '-') {
				return false
			}
		}
	}
	return true
}

func validateInstallationCode(code InstallationCode, now *time.Time) error {
	if code.Version != SchemaVersion {
		return errors.New("unsupported installation code version")
	}
	if err := ValidateEnrollmentURL(code.CentralURL); err != nil {
		return err
	}
	if !validIdentifier(code.AgentID, 128) || !validToken(code.Token, 32) {
		return errors.New("invalid installation agent identity or credential")
	}
	if code.ExpiresAt.IsZero() || code.ExpiresAt.Year() < 1970 || code.ExpiresAt.Year() > 9999 {
		return errors.New("invalid installation code expiry")
	}
	if now != nil && !now.Before(code.ExpiresAt) {
		return errors.New("installation code has expired")
	}
	if len(code.CAPEM) == 0 || len(code.CAPEM) > MaxInstallationCodeBytes {
		return errors.New("invalid installation CA size")
	}
	remaining := []byte(code.CAPEM)
	count := 0
	for len(bytes.TrimSpace(remaining)) > 0 {
		remaining = bytes.TrimSpace(remaining)
		if !bytes.HasPrefix(remaining, []byte("-----BEGIN CERTIFICATE-----")) {
			return errors.New("invalid installation CA encoding")
		}
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return errors.New("invalid installation CA encoding")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !certificate.IsCA || !certificate.BasicConstraintsValid || (certificate.KeyUsage != 0 && certificate.KeyUsage&x509.KeyUsageCertSign == 0) {
			return errors.New("installation trust must contain CA certificates")
		}
		if now != nil && (now.Before(certificate.NotBefore) || now.After(certificate.NotAfter)) {
			return errors.New("installation CA is outside its validity period")
		}
		remaining = rest
		count++
		if count > 8 {
			return errors.New("too many installation CA certificates")
		}
	}
	if count == 0 {
		return errors.New("installation code contains no CA certificate")
	}
	return nil
}

func uniqueInstallationFields(body []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(body))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return false
	}
	seen := make(map[string]bool)
	for decoder.More() {
		key, err := decoder.Token()
		name, ok := key.(string)
		if err != nil || !ok || seen[name] {
			return false
		}
		switch name {
		case "version", "central_url", "agent_id", "token", "ca_pem", "expires_at":
		default:
			return false
		}
		seen[name] = true
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return false
		}
	}
	_, err = decoder.Token()
	return err == nil
}
