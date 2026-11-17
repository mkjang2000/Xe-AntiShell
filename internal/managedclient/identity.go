package managedclient

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"strings"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

func GenerateCSR(agentID string) (keyPEM, csrPEM []byte, err error) {
	if !validAgentID(agentID) {
		return nil, nil, errors.New("invalid agent identity")
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return nil, nil, err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: agentID}}, private)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), nil
}

// ValidateEnrollment checks the issued leaf using the independently supplied
// CA and local private key, never the CA included in response.
func ValidateEnrollment(response managed.EnrollResponse, keyPEM, caPEM []byte, agentID string, now time.Time) error {
	roots, err := certificatePool(caPEM)
	if err != nil {
		return err
	}
	pair, err := tls.X509KeyPair([]byte(response.CertificatePEM), keyPEM)
	if err != nil {
		return errors.New("enrollment certificate does not match the local private key")
	}
	signer, ok := pair.PrivateKey.(crypto.Signer)
	if !ok {
		return errors.New("unsupported enrollment private key")
	}
	return validateEnrollmentPublic(response, signer.Public(), roots, agentID, now)
}

func validateEnrollmentPublic(response managed.EnrollResponse, public crypto.PublicKey, roots *x509.CertPool, agentID string, now time.Time) error {
	if response.AgentID != agentID || !validAgentID(agentID) || !validAgentID(response.EnrollmentID) || !validAgentID(response.PolicyKeyID) {
		return errors.New("invalid enrollment response identity")
	}
	if _, err := managed.DecodePublicKey(response.PolicyPublicKey); err != nil {
		return errors.New("invalid enrollment policy verification key")
	}
	if len(response.CertificatePEM) > 32<<10 {
		return errors.New("enrollment certificate exceeds its size limit")
	}
	var chain [][]byte
	remaining := []byte(response.CertificatePEM)
	for len(bytes.TrimSpace(remaining)) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" {
			return errors.New("invalid enrollment certificate encoding")
		}
		chain = append(chain, block.Bytes)
		remaining = rest
	}
	leaf, err := verifyClientCertificate(chain, roots, now)
	if err != nil {
		return err
	}
	if leaf.Subject.CommonName != agentID || len(leaf.Subject.OrganizationalUnit) != 1 || leaf.Subject.OrganizationalUnit[0] != response.EnrollmentID {
		return errors.New("enrollment certificate identity does not match the response")
	}
	expected, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return errors.New("invalid expected enrollment public key")
	}
	actual, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil || !bytes.Equal(actual, expected) {
		return errors.New("enrollment certificate public key does not match the request")
	}
	return nil
}

func certificatePool(caPEM []byte) (*x509.CertPool, error) {
	if len(caPEM) == 0 || len(caPEM) > 128<<10 {
		return nil, errors.New("a bounded pinned central CA is required")
	}
	pool := x509.NewCertPool()
	remaining := caPEM
	count := 0
	for len(bytes.TrimSpace(remaining)) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, errors.New("invalid pinned central CA")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !certificate.IsCA || !certificate.BasicConstraintsValid {
			return nil, errors.New("pinned central trust contains a non-CA certificate")
		}
		pool.AddCert(certificate)
		remaining = rest
		count++
		if count > 8 {
			return nil, errors.New("too many pinned central CA certificates")
		}
	}
	if count == 0 {
		return nil, errors.New("no pinned central CA certificates")
	}
	return pool, nil
}

func verifyClientCertificate(chain [][]byte, roots *x509.CertPool, now time.Time) (*x509.Certificate, error) {
	if len(chain) == 0 || len(chain) > 8 {
		return nil, errors.New("invalid client certificate chain")
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil || leaf.IsCA {
		return nil, errors.New("invalid client leaf certificate")
	}
	intermediates := x509.NewCertPool()
	for _, der := range chain[1:] {
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, errors.New("invalid client intermediate certificate")
		}
		intermediates.AddCert(certificate)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: now}); err != nil {
		return nil, errors.New("client certificate does not verify against pinned central trust")
	}
	if !validAgentID(leaf.Subject.CommonName) || len(leaf.Subject.OrganizationalUnit) != 1 || !validAgentID(leaf.Subject.OrganizationalUnit[0]) {
		return nil, errors.New("invalid client certificate enrollment identity")
	}
	return leaf, nil
}

func parseCSR(csrPEM, agentID string) (*x509.CertificateRequest, error) {
	if !validAgentID(agentID) || len(csrPEM) > 16<<10 {
		return nil, errors.New("invalid enrollment request identity or size")
	}
	block, rest := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("invalid enrollment certificate request")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil || csr.Subject.CommonName != agentID {
		return nil, errors.New("enrollment certificate request identity or signature is invalid")
	}
	if _, ok := csr.PublicKey.(ed25519.PublicKey); !ok {
		return nil, errors.New("enrollment requires an Ed25519 client key")
	}
	return csr, nil
}

func validAgentID(value string) bool {
	if value == "" || len(value) > 160 || value != strings.TrimSpace(value) {
		return false
	}
	for _, char := range value {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '-' || char == '_' || char == '.' || char == ':') {
			return false
		}
	}
	return true
}
