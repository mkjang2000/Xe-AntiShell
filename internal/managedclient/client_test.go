package managedclient

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

type testPKI struct {
	ca     *x509.Certificate
	key    ed25519.PrivateKey
	caPEM  []byte
	server tls.Certificate
}

func createTestPKI(t *testing.T) *testPKI {
	t.Helper()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, public, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	serverPublic, serverKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverCert := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "central.test"}, DNSNames: []string{"central.test"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverCert, ca, serverPublic, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		t.Fatal(err)
	}
	server, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatal(err)
	}
	return &testPKI{ca: ca, key: key, caPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), server: server}
}

func (p *testPKI) issue(t *testing.T, csrPEM []byte, agent, enrollment string) []byte {
	t.Helper()
	block, _ := pem.Decode(csrPEM)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	leaf := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: agent, OrganizationalUnit: []string{enrollment}}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, p.ca, csr.PublicKey, p.key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// Exercise the actual HTTP transport and TLS verification over memory pipes,
// requiring no network listener or host socket privileges in unit tests.
func pipeTransport(client *Client, pki *testPKI, handler http.Handler, requests *atomic.Int64) {
	transport := client.http.Transport.(*http.Transport)
	transport.DialContext = func(context.Context, string, string) (net.Conn, error) {
		local, remote := net.Pipe()
		go func() {
			defer remote.Close()
			_ = remote.SetDeadline(time.Now().Add(2 * time.Second))
			secure := tls.Server(remote, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pki.server}, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: client.roots})
			if err := secure.Handshake(); err != nil {
				return
			}
			request, err := http.ReadRequest(bufio.NewReader(secure))
			if err != nil {
				return
			}
			request.TLS = &tls.ConnectionState{}
			state := secure.ConnectionState()
			request.TLS = &state
			if requests != nil {
				requests.Add(1)
			}
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			response := recorder.Result()
			defer response.Body.Close()
			response.Close = true
			_ = response.Write(secure)
		}()
		return local, nil
	}
}

func TestClientEnrollmentAndAuthenticatedEndpoints(t *testing.T) {
	pki := createTestPKI(t)
	key, csr, err := GenerateCSR("agent-a")
	if err != nil {
		t.Fatal(err)
	}
	certificate := pki.issue(t, csr, "agent-a", "enrollment-a")
	public, _, err := managed.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	response := managed.EnrollResponse{AgentID: "agent-a", EnrollmentID: "enrollment-a", CertificatePEM: string(certificate), CAPEM: "untrusted replacement", PolicyKeyID: "key-a", PolicyPublicKey: managed.EncodePublicKey(public)}
	client, err := New("https://central.test", pki.caPEM, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	pipeTransport(client, pki, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/enroll" || r.Header.Get("Authorization") != "Bearer temporary-secret" {
			t.Error("unexpected enrollment request")
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(response)
	}), nil)
	enrolled, err := client.Enroll(context.Background(), "temporary-secret", managed.EnrollRequest{AgentID: "agent-a", CSRPEM: string(csr)})
	if err != nil {
		t.Fatal(err)
	}
	if enrolled.CAPEM != string(pki.caPEM) {
		t.Fatal("response replaced pinned CA trust")
	}
	if err := ValidateEnrollment(enrolled, key, pki.caPEM, "agent-a", time.Now()); err != nil {
		t.Fatal(err)
	}
	authenticated, err := New("https://central.test", pki.caPEM, certificate, key)
	if err != nil {
		t.Fatal(err)
	}
	defer authenticated.Close()
	pipeTransport(authenticated, pki, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) == 0 {
			t.Error("client identity not presented")
		}
		switch r.URL.Path {
		case "/v1/ingest":
			_ = json.NewEncoder(w).Encode(managed.Ack{SpoolID: "spool", Acknowledged: 1})
		case "/v1/heartbeat":
			_ = json.NewEncoder(w).Encode(map[string]string{"received_at": "now"})
		case "/v1/policy":
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Error("unexpected authenticated endpoint")
			w.WriteHeader(404)
		}
	}), nil)
	batch := managed.Batch{EnrollmentID: "enrollment-a", SpoolID: "spool", Records: []managed.Record{{Sequence: 1, Kind: managed.RecordKindAudit, ID: "audit-1", Payload: json.RawMessage(`{}`)}}}
	if _, err := authenticated.Ingest(context.Background(), batch); err != nil {
		t.Fatal(err)
	}
	if err := authenticated.Heartbeat(context.Background(), managed.Heartbeat{AgentID: "agent-a", EnrollmentID: "enrollment-a"}); err != nil {
		t.Fatal(err)
	}
	if policy, err := authenticated.Policy(context.Background()); err != nil || policy != nil {
		t.Fatalf("empty policy: %#v %v", policy, err)
	}
}

func TestClientRejectsWrongCAHostnameAndEnrollmentCertificate(t *testing.T) {
	pki := createTestPKI(t)
	other := createTestPKI(t)
	key, csr, err := GenerateCSR("agent-a")
	if err != nil {
		t.Fatal(err)
	}
	cert := pki.issue(t, csr, "agent-a", "enrollment-a")
	if _, err := New("https://central.test", other.caPEM, cert, key); err == nil {
		t.Fatal("wrong client CA accepted")
	}
	for _, test := range []struct {
		name, base string
		ca         []byte
		category   string
	}{
		{"wrong CA", "https://central.test", other.caPEM, "certificate_untrusted"},
		{"wrong hostname", "https://not-central.test", pki.caPEM, "certificate_hostname"},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, err := New(test.base, test.ca, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			pipeTransport(client, pki, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("untrusted TLS connection reached HTTP handler") }), nil)
			_, err = client.Enroll(context.Background(), "secret", managed.EnrollRequest{AgentID: "agent-a", CSRPEM: string(csr)})
			if !errors.Is(err, ErrTransport) || TransportCategory(err) != test.category {
				t.Fatalf("untrusted TLS error=%v", err)
			}
		})
	}
	public, _, _ := managed.GenerateSigningKey()
	response := managed.EnrollResponse{AgentID: "agent-a", EnrollmentID: "enrollment-a", CertificatePEM: string(cert), PolicyKeyID: "key", PolicyPublicKey: managed.EncodePublicKey(public)}
	otherKey, _, _ := GenerateCSR("agent-a")
	if err := ValidateEnrollment(response, otherKey, pki.caPEM, "agent-a", time.Now()); err == nil {
		t.Fatal("wrong local private key accepted")
	}
	response.EnrollmentID = "other-enrollment"
	if err := ValidateEnrollment(response, key, pki.caPEM, "agent-a", time.Now()); err == nil {
		t.Fatal("wrong enrollment certificate accepted")
	}
}

func TestClientRejectsUnsafeEndpointsMissingIdentityAndRedirect(t *testing.T) {
	pki := createTestPKI(t)
	for _, endpoint := range []string{"http://central.test", "https://user:password@central.test", "https://central.test?token=secret", "https://central.test#fragment", "https://central.test#", "https://central.test/a/../b", "https://central.test:99999"} {
		if _, err := New(endpoint, pki.caPEM, nil, nil); err == nil {
			t.Fatalf("unsafe endpoint accepted: %s", endpoint)
		}
	}
	if _, err := New("https://central.test", nil, nil, nil); err == nil {
		t.Fatal("missing CA accepted")
	}
	client, err := New("https://central.test", pki.caPEM, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Policy(context.Background()); !errors.Is(err, ErrIdentityRequired) {
		t.Fatalf("missingidentity error=%v", err)
	}
	var requests atomic.Int64
	pipeTransport(client, pki, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://attacker.test/steal")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}), &requests)
	_, csr, _ := GenerateCSR("agent")
	_, err = client.Enroll(context.Background(), "credential-not-in-errors", managed.EnrollRequest{AgentID: "agent", CSRPEM: string(csr)})
	var status *StatusError
	if !errors.As(err, &status) || status.Code != http.StatusTemporaryRedirect || requests.Load() != 1 {
		t.Fatalf("redirect response=%v requests=%d", err, requests.Load())
	}
	if strings.Contains(err.Error(), "credential-not-in-errors") {
		t.Fatal("enrollment credential leaked through error")
	}
}

func TestClientResponseBoundsAndAckScope(t *testing.T) {
	pki := createTestPKI(t)
	key, csr, _ := GenerateCSR("agent")
	cert := pki.issue(t, csr, "agent", "enrollment")
	client, err := New("https://central.test", pki.caPEM, cert, key)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	for _, body := range []string{strings.Repeat("x", managed.MaxPolicyBytes+1), `{"policy":{},"unknown":"field"}`} {
		pipeTransport(client, pki, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = fmt.Fprint(w, body) }), nil)
		if _, err := client.Policy(context.Background()); err == nil {
			t.Fatal("oversized or unsupported policy response accepted")
		}
	}
	batch := managed.Batch{EnrollmentID: "enrollment", SpoolID: "spool", Records: []managed.Record{{Sequence: 1, Kind: managed.RecordKindAudit, ID: "audit", Payload: json.RawMessage(`{}`)}}}
	for _, ack := range []managed.Ack{{SpoolID: "wrong", Acknowledged: 1}, {SpoolID: "spool", Acknowledged: 2}, {SpoolID: "spool", Acknowledged: 0}} {
		pipeTransport(client, pki, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _ = json.NewEncoder(w).Encode(ack) }), nil)
		if _, err := client.Ingest(context.Background(), batch); err == nil {
			t.Fatal("wrong or unsent acknowledgement accepted")
		}
	}
}
