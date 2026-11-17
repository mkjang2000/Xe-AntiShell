package managedclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"
	"testing"
)

type diagnosticTimeoutError struct{ text string }

func (e diagnosticTimeoutError) Error() string { return e.text }
func (diagnosticTimeoutError) Timeout() bool   { return true }
func (diagnosticTimeoutError) Temporary() bool { return true }

func TestTransportErrorClassifiesWithoutRetainingSensitiveCause(t *testing.T) {
	const secret = "private-token-recovery-and-request-value"
	certificate := &x509.Certificate{Subject: pkix.Name{CommonName: secret}, DNSNames: []string{secret}}
	tests := []struct {
		name, category string
		cause          error
	}{
		{"DNS lookup", "dns", &net.DNSError{Name: secret, Server: secret, Err: secret}},
		{"DNS timeout", "dns", &net.DNSError{Name: secret, Err: secret, IsTimeout: true}},
		{"connection refused", "connection_refused", &net.OpError{Op: "dial", Net: "tcp", Err: &os.SyscallError{Syscall: "connect", Err: syscall.ECONNREFUSED}}},
		{"network unreachable", "network_unreachable", syscall.ENETUNREACH},
		{"host unreachable", "network_unreachable", syscall.EHOSTUNREACH},
		{"access denied", "permission_denied", syscall.EACCES},
		{"operation denied", "permission_denied", syscall.EPERM},
		{"dial timeout", "timeout", &net.OpError{Op: "dial", Net: "tcp", Err: diagnosticTimeoutError{secret}}},
		{"request timeout", "timeout", diagnosticTimeoutError{secret}},
		{"untrusted CA", "certificate_untrusted", x509.UnknownAuthorityError{Cert: certificate}},
		{"unavailable roots", "certificate_untrusted", x509.SystemRootsError{Err: errors.New(secret)}},
		{"hostname mismatch", "certificate_hostname", x509.HostnameError{Certificate: certificate, Host: secret}},
		{"invalid certificate", "certificate_invalid", x509.CertificateInvalidError{Cert: certificate, Reason: x509.Expired, Detail: secret}},
		{"wrapped certificate verification", "certificate_hostname", &tls.CertificateVerificationError{Err: x509.HostnameError{Certificate: certificate, Host: secret}}},
		{"other certificate verification", "certificate_invalid", &tls.CertificateVerificationError{Err: errors.New(secret)}},
		{"invalid TLS record", "tls", tls.RecordHeaderError{Msg: secret}},
		{"plain HTTP response", "tls", http.ErrSchemeMismatch},
		{"TLS alert", "tls", tls.AlertError(40)},
		{"remote TLS alert", "tls", &net.OpError{Op: "remote error", Err: errors.New(secret)}},
		{"unknown connection error", "connection", errors.New(secret)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cause := &url.Error{Op: "Post", URL: "https://" + secret + "/v1/enroll", Err: fmt.Errorf("%s: %w", secret, test.cause)}
			err := classifyTransportError(cause)
			if got := TransportCategory(err); got != test.category {
				t.Fatalf("category=%q, want %q", got, test.category)
			}
			if !errors.Is(err, ErrTransport) || errors.Unwrap(err) != ErrTransport {
				t.Fatal("transport sentinel compatibility was lost")
			}
			if strings.Contains(fmt.Sprintf("%v %+v %#v", err, err, err), secret) {
				t.Fatal("transport diagnostic retained sensitive error text")
			}
			var requestError *url.Error
			if errors.As(err, &requestError) {
				t.Fatal("transport diagnostic retained the original request error")
			}
		})
	}
}

func TestTransportCategoryRejectsArbitraryErrorsAndCategoryText(t *testing.T) {
	const secret = "untrusted-private-category"
	for _, err := range []error{nil, ErrTransport, errors.New(secret), &StatusError{Code: http.StatusUnauthorized}, &TransportError{Category: secret}, (*TransportError)(nil)} {
		if got := TransportCategory(err); got != "" {
			t.Fatal("unrecognized error produced a transport category")
		}
	}
	for _, err := range []*TransportError{nil, {}, {Category: secret}} {
		if err.Error() != ErrTransport.Error() {
			t.Fatal("unrecognized category was reflected in the error message")
		}
	}
	err := fmt.Errorf("outer error: %w", &TransportError{Category: "dns"})
	if got := TransportCategory(err); got != "dns" {
		t.Fatalf("wrapped category=%q", got)
	}
}

type diagnosticRoundTripper func(*http.Request) (*http.Response, error)

func (f diagnosticRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestRequestReturnsSafeTypedTransportError(t *testing.T) {
	pki := createTestPKI(t)
	for _, test := range []struct {
		name, category string
		cause          error
	}{
		{"DNS", "dns", &net.DNSError{Name: "private-host", Err: "private-credential"}},
		{"refused", "connection_refused", &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, err := New("https://private-host", pki.caPEM, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			client.http.Transport.(*http.Transport).DialContext = func(context.Context, string, string) (net.Conn, error) {
				return nil, test.cause
			}
			_, err = client.request(context.Background(), http.MethodPost, "/v1/enroll", "private-credential", nil, nil, 0)
			if TransportCategory(err) != test.category || !errors.Is(err, ErrTransport) {
				t.Fatalf("unexpected transport diagnostic: %v", err)
			}
			if strings.Contains(err.Error(), "private-") {
				t.Fatal("request diagnostic exposed request or resolver data")
			}
		})
	}
}

func TestRequestRetainsCallerCancellation(t *testing.T) {
	pki := createTestPKI(t)
	client, err := New("https://central.test", pki.caPEM, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client.http.Transport = diagnosticRoundTripper(func(*http.Request) (*http.Response, error) {
		cancel()
		return nil, errors.New("private-cancellation-cause")
	})
	_, err = client.request(ctx, http.MethodPost, "/v1/enroll", "private-credential", nil, nil, 0)
	if err != context.Canceled || TransportCategory(err) != "" {
		t.Fatalf("caller cancellation behavior changed: %v", err)
	}
}
