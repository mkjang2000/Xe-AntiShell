package agent

import (
	"bytes"
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
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"xe-antishell/internal/config"
	"xe-antishell/internal/managedclient"
	"xe-antishell/internal/storage"
)

// This isolated TLS central issues a client certificate for the actual CSR so
// retries exercise pinned trust, durable identity, and response validation.
type enrollmentCentralFixture struct {
	policyKey ed25519.PrivateKey
	server    *httptest.Server
	caPEM     []byte
	status    atomic.Int64
	requests  atomic.Int64
}

func newEnrollmentCentralFixture(t *testing.T) *enrollmentCentralFixture {
	t.Helper()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Enrollment Test Root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, public, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &enrollmentCentralFixture{caPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
	pair, err := tls.X509KeyPair(fixture.caPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatal(err)
	}
	policyPublic, policyKey, err := managed.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	fixture.policyKey = policyKey
	fixture.status.Store(http.StatusCreated)
	fixture.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fixture.requests.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != "/v1/enroll" {
			t.Error("unexpected enrollment endpoint")
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if status := int(fixture.status.Load()); status != http.StatusCreated {
			w.WriteHeader(status)
			_, _ = w.Write([]byte("private response body token-private-response"))
			return
		}
		var request managed.EnrollRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error("invalid enrollment fixture request")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		block, _ := pem.Decode([]byte(request.CSRPEM))
		if block == nil {
			t.Error("missing enrollment fixture CSR")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			t.Error("invalid enrollment fixture CSR")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: request.AgentID, OrganizationalUnit: []string{"enrollment-test"}}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(30 * time.Minute), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		certificate, err := x509.CreateCertificate(rand.Reader, leaf, ca, csr.PublicKey, key)
		if err != nil {
			t.Error("could not issue enrollment fixture certificate")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(managed.EnrollResponse{AgentID: request.AgentID, EnrollmentID: "enrollment-test", CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate})), PolicyKeyID: "policy-test", PolicyPublicKey: managed.EncodePublicKey(policyPublic)})
	}))
	fixture.server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}}
	fixture.server.StartTLS()
	t.Cleanup(fixture.server.Close)
	return fixture
}

func enrollmentRecoveryCode(t *testing.T) string {
	t.Helper()
	code, err := managed.NewChallenge()
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func TestEnrollmentPendingMismatchRecordsSafeStatus(t *testing.T) {
	service, store := newTestService(t, config.CollectorDisabled, nil)
	defer store.Close()
	central := newEnrollmentCentralFixture(t)
	ctx := context.Background()
	pending := storage.PendingEnrollment{URL: "https://private-central.example", AgentID: "agent-test", CAPEM: string(central.caPEM), KeyPEM: "private-key-secret", CSRPEM: "private-csr-secret"}
	if err := store.SavePendingEnrollment(ctx, pending); err != nil {
		t.Fatal(err)
	}
	if _, err := service.EnrollWithRecovery(ctx, central.server.URL, "agent-test", central.caPEM, "token-private-request", enrollmentRecoveryCode(t)); err == nil {
		t.Fatal("accepted a different pending identity")
	}
	status, err := service.ManagedStatus(ctx)
	if err != nil || status.LastError != "central enrollment blocked: pending identity differs from supplied central identity" || status.Enrolled {
		t.Fatalf("pending mismatch was not reported: %#v %v", status, err)
	}
	if central.requests.Load() != 0 {
		t.Fatal("pending identity mismatch reached central")
	}
	retained, err := store.PendingEnrollment(ctx)
	if err != nil || retained != pending {
		t.Fatal("pending identity changed after a rejected retry")
	}
}

func TestEnrollmentConnectionRefusedRecordsStatus(t *testing.T) {
	service, store := newTestService(t, config.CollectorDisabled, nil)
	defer store.Close()
	central := newEnrollmentCentralFixture(t)
	central.server.Close()
	if _, err := service.EnrollWithRecovery(context.Background(), central.server.URL, "agent-test", central.caPEM, "token-private-request", enrollmentRecoveryCode(t)); err == nil {
		t.Fatal("enrollment succeeded with no central listener")
	}
	status, err := service.ManagedStatus(context.Background())
	if err != nil || status.LastError != "central enrollment failed: connection refused" {
		t.Fatalf("connection failure was not reported: %#v %v", status, err)
	}
}

func TestEnrollmentRetryAndIdempotentSuccessClearOnlyEnrollmentFailure(t *testing.T) {
	service, store := newTestService(t, config.CollectorDisabled, nil)
	defer store.Close()
	central := newEnrollmentCentralFixture(t)
	central.status.Store(http.StatusUnauthorized)
	ctx, code := context.Background(), enrollmentRecoveryCode(t)
	const deliveryFailure = "central event delivery failed; records retained for retry"
	service.managedError("delivery", deliveryFailure)
	if _, err := service.EnrollWithRecovery(ctx, central.server.URL, "agent-test", central.caPEM, "token-private-request", code); err == nil {
		t.Fatal("unauthorized enrollment succeeded")
	}
	status, err := service.ManagedStatus(ctx)
	if err != nil || status.LastError != "central enrollment rejected (HTTP 401); "+deliveryFailure {
		t.Fatalf("HTTP failure missing or nondeterministic: %#v %v", status, err)
	}
	pending, err := store.PendingEnrollment(ctx)
	if err != nil {
		t.Fatal(err)
	}
	central.status.Store(http.StatusCreated)
	if got, err := service.EnrollWithRecovery(ctx, central.server.URL, "agent-test", central.caPEM, "token-private-request", code); err != nil || got != code {
		t.Fatalf("enrollment retry failed: %v", err)
	}
	t.Cleanup(func() { service.managedRuntime.client.Close() })
	state, err := store.ManagedState(ctx)
	if err != nil || state.KeyPEM != pending.KeyPEM {
		t.Fatal("enrollment retry replaced the pending private key")
	}
	status, err = service.ManagedStatus(ctx)
	if err != nil || !status.Enrolled || status.LastError != deliveryFailure {
		t.Fatalf("successful enrollment cleared another operation: %#v %v", status, err)
	}
	if _, err := service.EnrollWithRecovery(ctx, central.server.URL, "agent-test", central.caPEM, "token-private-request", enrollmentRecoveryCode(t)); err == nil {
		t.Fatal("existing enrollment accepted a different recovery code")
	}
	status, err = service.ManagedStatus(ctx)
	if err != nil || !strings.HasPrefix(status.LastError, "central enrollment blocked: agent is already enrolled") {
		t.Fatalf("existing identity mismatch was not reported: %#v %v", status, err)
	}
	if _, err := service.EnrollWithRecovery(ctx, central.server.URL, "agent-test", central.caPEM, "unused-private-token", code); err != nil {
		t.Fatalf("idempotent enrollment failed: %v", err)
	}
	status, err = service.ManagedStatus(ctx)
	if err != nil || status.LastError != deliveryFailure || central.requests.Load() != 2 {
		t.Fatalf("idempotent success failed to recover independently: %#v %v requests=%d", status, err, central.requests.Load())
	}
}

func TestEnrollmentDiagnosticsNeverReflectSecretErrors(t *testing.T) {
	service, store := newTestService(t, config.CollectorDisabled, nil)
	defer store.Close()
	var journal bytes.Buffer
	logger := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&journal, nil)))
	t.Cleanup(func() { slog.SetDefault(logger) })
	const secret = "https://private-central.example token-private-request recovery-private-code private-key-secret private-csr-secret\nprivate-journal-line"
	for _, test := range []struct {
		stage enrollmentStage
		err   error
	}{
		{enrollmentPendingIdentityMismatch, errors.New(secret)},
		{enrollmentExistingIdentityMismatch, errors.New(secret)},
		{enrollmentLocalState, errors.New(secret)},
		{enrollmentInvalidSetup, errors.New(secret)},
		{enrollmentInvalidResponse, errors.New(secret)},
		{enrollmentCentralRequest, errors.New(secret)},
		{enrollmentCentralRequest, fmt.Errorf("%s: %w", secret, &managedclient.StatusError{Code: http.StatusUnauthorized})},
		{enrollmentCentralRequest, &managedclient.StatusError{Code: 987654321}},
		{enrollmentCentralRequest, fmt.Errorf("%s: %w", secret, &managedclient.TransportError{Category: "dns"})},
		{enrollmentCentralRequest, &managedclient.TransportError{Category: secret}},
		{enrollmentCentralRequest, fmt.Errorf("%s: %w", secret, context.Canceled)},
		{enrollmentCentralRequest, fmt.Errorf("%s: %w", secret, context.DeadlineExceeded)},
	} {
		service.recordEnrollmentResult(test.stage, test.err)
		status, err := service.ManagedStatus(context.Background())
		if err != nil || status.LastError == "" {
			t.Fatal("enrollment failure was not retained")
		}
		for _, value := range append(strings.Fields(secret), "987654321") {
			if strings.Contains(status.LastError, value) || strings.Contains(journal.String(), value) {
				t.Fatal("secret error content reached enrollment diagnostics")
			}
		}
	}
	if !strings.Contains(journal.String(), `"category":"dns"`) || !strings.Contains(journal.String(), `"http_status":401`) {
		t.Fatal("journal lost safe enrollment classifications")
	}
}
