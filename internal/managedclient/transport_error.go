package managedclient

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"syscall"
)

// TransportError retains only an allowlisted category, never a peer message,
// request URL, or the underlying error that may contain sensitive values.
type TransportError struct {
	Category string
}

func (e *TransportError) Error() string {
	if e != nil {
		switch e.Category {
		case "dns":
			return "central connection failed (DNS lookup failed)"
		case "connection_refused":
			return "central connection failed (connection refused)"
		case "network_unreachable":
			return "central connection failed (network unreachable)"
		case "permission_denied":
			return "central connection failed (network permission denied)"
		case "timeout":
			return "central connection failed (connection timed out)"
		case "certificate_untrusted":
			return "central connection failed (server certificate is not trusted)"
		case "certificate_hostname":
			return "central connection failed (server certificate hostname mismatch)"
		case "certificate_invalid":
			return "central connection failed (server certificate is invalid)"
		case "tls":
			return "central connection failed (TLS handshake failed)"
		}
	}
	return ErrTransport.Error()
}

func (*TransportError) Unwrap() error { return ErrTransport }

// TransportCategory reports only recognized categories from a TransportError.
// Arbitrary errors and unknown category values are deliberately not reflected.
func TransportCategory(err error) string {
	var transport *TransportError
	if !errors.As(err, &transport) || transport == nil {
		return ""
	}
	switch transport.Category {
	case "dns", "connection_refused", "network_unreachable", "permission_denied", "timeout", "certificate_untrusted", "certificate_hostname", "certificate_invalid", "tls", "connection":
		return transport.Category
	default:
		return ""
	}
}

func classifyTransportError(err error) *TransportError {
	category := "connection"
	var unknownAuthority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalidCertificate x509.CertificateInvalidError
	var systemRoots x509.SystemRootsError
	var certificateVerification *tls.CertificateVerificationError
	var dns *net.DNSError
	var recordHeader tls.RecordHeaderError
	var alert tls.AlertError
	var operation *net.OpError
	switch {
	case errors.As(err, &unknownAuthority), errors.As(err, &systemRoots):
		category = "certificate_untrusted"
	case errors.As(err, &hostname):
		category = "certificate_hostname"
	case errors.As(err, &invalidCertificate), errors.As(err, &certificateVerification):
		category = "certificate_invalid"
	case errors.As(err, &dns):
		category = "dns"
	case transportTimedOut(err):
		category = "timeout"
	case errors.Is(err, syscall.ECONNREFUSED):
		category = "connection_refused"
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH):
		category = "network_unreachable"
	case errors.Is(err, syscall.EACCES), errors.Is(err, syscall.EPERM):
		category = "permission_denied"
	case errors.Is(err, http.ErrSchemeMismatch), errors.As(err, &recordHeader), errors.As(err, &alert):
		category = "tls"
	case errors.As(err, &operation) && operation.Op == "remote error":
		// crypto/tls wraps remote TLS alerts in a net.OpError. The alert
		// itself is an unexported type; its text must not be inspected.
		category = "tls"
	}
	return &TransportError{Category: category}
}

func transportTimedOut(err error) bool {
	if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		return true
	}
	// A url.Error or net.OpError may report false when an intermediate
	// wrapper does not itself implement net.Error. Inspect nested causes too.
	switch wrapped := err.(type) {
	case interface{ Unwrap() error }:
		return transportTimedOut(wrapped.Unwrap())
	case interface{ Unwrap() []error }:
		for _, cause := range wrapped.Unwrap() {
			if transportTimedOut(cause) {
				return true
			}
		}
	}
	return false
}
