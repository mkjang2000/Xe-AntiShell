// Package managedclient provides bounded authenticated HTTPS calls to central.
// It never trusts CA replacement data from an enrollment response.
package managedclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

const maxRequestBytes = 4 << 20
const maxResponseBytes = 1 << 20

var ErrTransport = errors.New("central connection failed")
var ErrIdentityRequired = errors.New("central request requires an enrolled client identity")

type StatusError struct{ Code int }

func (e *StatusError) Error() string {
	return fmt.Sprintf("central request rejected (HTTP %d)", e.Code)
}

type Client struct {
	base          url.URL
	http          *http.Client
	caPEM         []byte
	roots         *x509.CertPool
	authenticated bool
}

func New(baseURL string, caPEM, certPEM, keyPEM []byte) (*Client, error) {
	u, err := url.Parse(baseURL)
	if err != nil || baseURL != strings.TrimSpace(baseURL) || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || strings.Contains(baseURL, "#") || u.Fragment != "" || u.RawPath != "" {
		return nil, errors.New("central endpoint must be an HTTPS URL without credentials, query, or fragment")
	}
	if u.Path != "" && path.Clean(u.Path) != strings.TrimSuffix(u.Path, "/") && u.Path != "/" {
		return nil, errors.New("central endpoint path is not canonical")
	}
	if p := u.Port(); p != "" {
		number, err := strconv.Atoi(p)
		if err != nil || number < 1 || number > 65535 {
			return nil, errors.New("invalid central endpoint port")
		}
	}
	roots, err := certificatePool(caPEM)
	if err != nil {
		return nil, err
	}
	tlsConfig := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}
	if len(certPEM) != 0 || len(keyPEM) != 0 {
		if len(certPEM) == 0 || len(keyPEM) == 0 {
			return nil, errors.New("both client certificate and private key are required")
		}
		pair, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return nil, errors.New("invalid client certificate or key pair")
		}
		if _, err := verifyClientCertificate(pair.Certificate, roots, time.Now()); err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{pair}
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{TLSClientConfig: tlsConfig, DialContext: dialer.DialContext, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second, IdleConnTimeout: 60 * time.Second, MaxIdleConns: 4, MaxConnsPerHost: 4, DisableCompression: true}
	return &Client{base: *u, http: &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, caPEM: append([]byte(nil), caPEM...), roots: roots, authenticated: len(tlsConfig.Certificates) != 0}, nil
}

func (c *Client) Close() { c.http.CloseIdleConnections() }

func (c *Client) Enroll(ctx context.Context, token string, request managed.EnrollRequest) (managed.EnrollResponse, error) {
	var response managed.EnrollResponse
	token = strings.TrimSpace(token)
	if token == "" || len(token) > 512 || strings.ContainsAny(token, "\r\n\t ") {
		return response, errors.New("invalid enrollment credential")
	}
	csr, err := parseCSR(request.CSRPEM, request.AgentID)
	if err != nil {
		return response, err
	}
	_, err = c.request(ctx, http.MethodPost, "/v1/enroll", token, request, &response, 64<<10)
	if err != nil {
		return managed.EnrollResponse{}, err
	}
	if err := validateEnrollmentPublic(response, csr.PublicKey, c.roots, request.AgentID, time.Now()); err != nil {
		return managed.EnrollResponse{}, err
	}
	// The response CA is informational. Never replace the independently pinned
	// root set with trust material returned by a network peer.
	response.CAPEM = string(c.caPEM)
	return response, nil
}

func (c *Client) Ingest(ctx context.Context, batch managed.Batch) (managed.Ack, error) {
	var ack managed.Ack
	if !c.authenticated {
		return ack, ErrIdentityRequired
	}
	if err := batch.Validate(); err != nil {
		return ack, err
	}
	_, err := c.request(ctx, http.MethodPost, "/v1/ingest", "", batch, &ack, 16<<10)
	if err != nil {
		return managed.Ack{}, err
	}
	if ack.SpoolID != batch.SpoolID || ack.Acknowledged != batch.Records[len(batch.Records)-1].Sequence {
		return managed.Ack{}, errors.New("invalid central delivery acknowledgement")
	}
	return ack, nil
}

func (c *Client) Heartbeat(ctx context.Context, heartbeat managed.Heartbeat) error {
	if !c.authenticated {
		return ErrIdentityRequired
	}
	_, err := c.request(ctx, http.MethodPost, "/v1/heartbeat", "", heartbeat, nil, 16<<10)
	return err
}

func (c *Client) Policy(ctx context.Context) (*managed.SignedPolicy, error) {
	if !c.authenticated {
		return nil, ErrIdentityRequired
	}
	var policy managed.SignedPolicy
	status, err := c.request(ctx, http.MethodGet, "/v1/policy", "", nil, &policy, managed.MaxPolicyBytes)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNoContent {
		return nil, nil
	}
	return &policy, nil
}

func (c *Client) request(ctx context.Context, method, endpoint, token string, input, output any, maximum int) (int, error) {
	var body []byte
	if input != nil {
		var err error
		body, err = json.Marshal(input)
		if err != nil {
			return 0, errors.New("central request cannot be encoded")
		}
		if len(body) > maxRequestBytes {
			return 0, errors.New("central request exceeds its size limit")
		}
	}
	u := c.base
	u.Path = strings.TrimRight(u.Path, "/") + endpoint
	request, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return 0, errors.New("central request cannot be created")
	}
	request.Header.Set("Accept", "application/json")
	if input != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := c.http.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		return 0, classifyTransportError(err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return response.StatusCode, &StatusError{Code: response.StatusCode}
	}
	if response.StatusCode == http.StatusNoContent {
		return response.StatusCode, nil
	}
	if maximum < 1 || maximum > maxResponseBytes {
		maximum = maxResponseBytes
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, int64(maximum)+1))
	if err != nil {
		return 0, errors.New("central response could not be read")
	}
	if len(data) > maximum {
		return 0, errors.New("central response exceeds its size limit")
	}
	if output != nil {
		if err := managed.DecodeStrict(data, maximum, output); err != nil {
			return 0, errors.New("central response contains invalid JSON")
		}
	}
	return response.StatusCode, nil
}
