package managed

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strings"
	"time"
)

const MaxRemovalGrantLifetime = 15 * time.Minute

type RemovalGrant struct {
	ID           string    `json:"grant_id"`
	AgentID      string    `json:"agent_id"`
	EnrollmentID string    `json:"enrollment_id"`
	Challenge    string    `json:"challenge"`
	Action       string    `json:"action"`
	IssuedAt     time.Time `json:"issued_at"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type SignedRemovalGrant struct {
	Grant     RemovalGrant `json:"grant"`
	KeyID     string       `json:"key_id"`
	Signature string       `json:"signature"`
}

type RecoveryVerifier struct {
	Version      string `json:"version"`
	ID           string `json:"id"`
	AgentID      string `json:"agent_id"`
	EnrollmentID string `json:"enrollment_id"`
	Digest       string `json:"digest"`
}

func NewChallenge() (string, error) { return randomToken(32) }

func (g RemovalGrant) Validate() error {
	if !validIdentifier(g.ID, 160) || !validIdentifier(g.AgentID, 128) || !validIdentifier(g.EnrollmentID, 160) || !validToken(g.Challenge, 32) || g.Action != "uninstall" {
		return errors.New("invalid removal grant identity, challenge, or action")
	}
	if g.IssuedAt.IsZero() || !g.ExpiresAt.After(g.IssuedAt) || g.ExpiresAt.Sub(g.IssuedAt) > MaxRemovalGrantLifetime {
		return errors.New("invalid removal grant validity interval")
	}
	return nil
}

func SignRemovalGrant(grant RemovalGrant, keyID string, private ed25519.PrivateKey) (SignedRemovalGrant, error) {
	if err := grant.Validate(); err != nil {
		return SignedRemovalGrant{}, err
	}
	signature, err := signValue("removal", keyID, grant, private, 16<<10)
	return SignedRemovalGrant{Grant: grant, KeyID: keyID, Signature: signature}, err
}

// VerifyRemovalGrant establishes authenticity and scope only. The caller must
// atomically consume the grant/challenge before beginning any removal work.
func VerifyRemovalGrant(signed SignedRemovalGrant, trusted map[string]ed25519.PublicKey, agentID, enrollmentID, challenge string, now time.Time) (RemovalGrant, error) {
	if err := verifyValue("removal", signed.KeyID, signed.Grant, signed.Signature, trusted, 16<<10); err != nil {
		return RemovalGrant{}, err
	}
	grant := signed.Grant
	if err := grant.Validate(); err != nil {
		return RemovalGrant{}, err
	}
	if grant.AgentID != agentID || grant.EnrollmentID != enrollmentID || grant.Challenge != challenge {
		return RemovalGrant{}, errors.New("removal grant does not match this operation")
	}
	if grant.IssuedAt.After(now.Add(time.Minute)) || !now.Before(grant.ExpiresAt) {
		return RemovalGrant{}, errors.New("removal grant is expired or not yet valid")
	}
	return grant, nil
}

func GenerateRecoveryCode(agentID, enrollmentID string) (string, RecoveryVerifier, error) {
	if !validIdentifier(agentID, 128) || !validIdentifier(enrollmentID, 160) {
		return "", RecoveryVerifier{}, errors.New("invalid recovery enrollment identity")
	}
	code, err := randomToken(32)
	if err != nil {
		return "", RecoveryVerifier{}, err
	}
	verifier, err := NewRecoveryVerifier(agentID, enrollmentID, code)
	return code, verifier, err
}

// NewRecoveryVerifier binds a pre-generated administrator recovery code to the
// completed enrollment. Callers can fsync the code outside agent state before
// making the first network request, avoiding loss after an interrupted reply.
func NewRecoveryVerifier(agentID, enrollmentID, code string) (RecoveryVerifier, error) {
	if !validIdentifier(agentID, 128) || !validIdentifier(enrollmentID, 160) || !validToken(code, 32) {
		return RecoveryVerifier{}, errors.New("invalid recovery code or enrollment identity")
	}
	id, err := randomToken(16)
	if err != nil {
		return RecoveryVerifier{}, err
	}
	verifier := RecoveryVerifier{Version: SchemaVersion, ID: id, AgentID: agentID, EnrollmentID: enrollmentID}
	verifier.Digest = recoveryDigest(verifier, code)
	return verifier, nil
}

// VerifyRecoveryCode does not consume a code. The caller owns durable,
// concurrency-safe single-use state, operation resumption, and audit storage.
func VerifyRecoveryCode(verifier RecoveryVerifier, agentID, enrollmentID, candidate string) bool {
	candidate = strings.TrimSpace(candidate)
	if !validIdentifier(agentID, 128) || !validIdentifier(enrollmentID, 160) || verifier.Version != SchemaVersion || verifier.AgentID != agentID || verifier.EnrollmentID != enrollmentID || !validToken(verifier.ID, 16) || !validToken(candidate, 32) || !validToken(verifier.Digest, 32) {
		return false
	}
	actual := recoveryDigest(verifier, candidate)
	return subtle.ConstantTimeCompare([]byte(actual), []byte(verifier.Digest)) == 1
}

func recoveryDigest(verifier RecoveryVerifier, code string) string {
	// A cryptographically random 256-bit code resists offline guessing without
	// a password KDF; the digest additionally binds agent, generation, and ID.
	material := "xe-antishell-managed/v1/recovery\x00" + verifier.AgentID + "\x00" + verifier.EnrollmentID + "\x00" + verifier.ID + "\x00" + code
	digest := sha256.Sum256([]byte(material))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func randomToken(bytes int) (string, error) {
	value := make([]byte, bytes)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func validToken(value string, bytes int) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == bytes && base64.RawURLEncoding.EncodeToString(decoded) == value
}
