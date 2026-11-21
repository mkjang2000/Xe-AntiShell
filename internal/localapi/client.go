package localapi

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"xe-antishell/internal/model"
)

type Client struct {
	http                 *http.Client
	panelAccessSupported atomic.Bool
}

type localAPIStatusError struct {
	code    int
	message string
}

func (e *localAPIStatusError) Error() string { return e.message }

const (
	auditForwardQueueSize = 256
	auditSendTimeout      = time.Second
	auditRetryInitial     = 100 * time.Millisecond
	auditRetryMaximum     = 5 * time.Second
	auditLossLogInterval  = time.Minute
)

type auditForwardStats struct {
	dropped      uint64
	sendFailures uint64
	firstError   error
}

func NewClient(socketPath string) *Client {
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socketPath)
		},
		DisableCompression: true,
	}
	return &Client{http: &http.Client{Transport: transport, Timeout: 30 * time.Second}}
}

func (c *Client) Status(ctx context.Context) (model.AgentStatus, error) {
	var value model.AgentStatus
	err := c.get(ctx, "/v1/status", &value)
	return value, err
}

func (c *Client) Capabilities(ctx context.Context) (model.CapabilityReport, error) {
	var value model.CapabilityReport
	err := c.get(ctx, "/v1/capabilities", &value)
	return value, err
}

func (c *Client) RefreshCapabilities(ctx context.Context) (model.CapabilityReport, error) {
	var value model.CapabilityReport
	err := c.request(ctx, http.MethodPost, "/v1/capabilities/refresh", nil, &value)
	return value, err
}

func (c *Client) Events(ctx context.Context, limit int) ([]model.Event, error) {
	var value []model.Event
	err := c.get(ctx, "/v1/events?limit="+strconv.Itoa(limit), &value)
	return value, err
}

func (c *Client) Findings(ctx context.Context, limit int) ([]model.Finding, error) {
	var value []model.Finding
	err := c.get(ctx, "/v1/findings?limit="+strconv.Itoa(limit), &value)
	return value, err
}

func (c *Client) ProcessTree(ctx context.Context, pid int) ([]model.Process, error) {
	var value []model.Process
	err := c.get(ctx, "/v1/process-tree?pid="+strconv.Itoa(pid), &value)
	return value, err
}

// StreamAudit forwards dispatcher records without buffering the entire input.
func (c *Client) StreamAudit(ctx context.Context, input io.Reader, maxLine int) error {
	if maxLine < 1 {
		return errors.New("maximum audit line size must be positive")
	}
	scanner := bufio.NewScanner(input)
	scannerMaximum := maxLine
	if maxLine < int(^uint(0)>>1) {
		scannerMaximum++
	}
	initialBuffer := 64 * 1024
	if scannerMaximum < initialBuffer {
		initialBuffer = scannerMaximum
	}
	scanner.Buffer(make([]byte, initialBuffer), scannerMaximum)
	lines := make(chan []byte, auditForwardQueueSize)
	result := make(chan auditForwardStats, 1)
	go func() { result <- c.forwardAuditLines(ctx, lines) }()

	var readerDropped uint64
	var readerErr error
	var lastQueueWarning time.Time
scanLoop:
	for scanner.Scan() {
		if len(scanner.Bytes()) > maxLine {
			readerErr = fmt.Errorf("audit input line exceeds %d bytes", maxLine)
			break
		}
		if strings.TrimSpace(scanner.Text()) == "" {
			continue
		}
		line := append([]byte(nil), scanner.Bytes()...)
		if err := ctx.Err(); err != nil {
			readerErr = err
			break
		}
		select {
		case lines <- line:
		case <-ctx.Done():
			readerErr = ctx.Err()
			break scanLoop
		default:
			readerDropped++
			now := time.Now()
			if lastQueueWarning.IsZero() || now.Sub(lastQueueWarning) >= auditLossLogInterval {
				slog.Warn("audit forwarding queue is full; records are being dropped",
					"dropped_total", readerDropped,
					"queue_size", auditForwardQueueSize,
				)
				lastQueueWarning = now
			}
		}
	}
	if err := scanner.Err(); err != nil && readerErr == nil {
		readerErr = fmt.Errorf("read audit input: %w", err)
	}
	close(lines)
	stats := <-result
	stats.dropped += readerDropped
	if readerErr != nil || stats.dropped != 0 || stats.sendFailures != 0 {
		cause := errors.Join(readerErr, stats.firstError)
		if cause == nil {
			cause = errors.New("audit records were dropped")
		}
		return fmt.Errorf("audit forwarding incomplete: dropped=%d send_failures=%d: %w",
			stats.dropped, stats.sendFailures, cause)
	}
	return nil
}

func (c *Client) forwardAuditLines(ctx context.Context, lines <-chan []byte) auditForwardStats {
	var stats auditForwardStats
	var retryAt time.Time
	var retryDelay time.Duration
	var outageDropped uint64
	var outageFailures uint64
	var lastOutageWarning time.Time
	for line := range lines {
		now := time.Now()
		if !retryAt.IsZero() && now.Before(retryAt) {
			stats.dropped++
			outageDropped++
			if lastOutageWarning.IsZero() || now.Sub(lastOutageWarning) >= auditLossLogInterval {
				slog.Warn("sentineld is unavailable; audit records are being dropped during backoff",
					"dropped_since_outage", outageDropped,
					"send_failures_since_outage", outageFailures,
					"retry_at", retryAt,
				)
				lastOutageWarning = now
			}
			continue
		}
		sendCtx, cancel := context.WithTimeout(ctx, auditSendTimeout)
		err := c.request(sendCtx, http.MethodPost, "/v1/ingest/audit", line, nil)
		cancel()
		if err != nil {
			stats.sendFailures++
			outageFailures++
			if stats.firstError == nil {
				stats.firstError = err
			}
			if retryDelay == 0 {
				retryDelay = auditRetryInitial
			} else {
				retryDelay = min(retryDelay*2, auditRetryMaximum)
			}
			retryAt = time.Now().Add(retryDelay)
			continue
		}
		// A successful request proves that the daemon and its socket are
		// available again. Reset the circuit so subsequent records are sent
		// immediately. Records dropped during an outage remain visible in the
		// aggregate result if auditd later closes the plugin input.
		if outageFailures != 0 || outageDropped != 0 {
			slog.Info("audit forwarding recovered",
				"dropped_since_outage", outageDropped,
				"send_failures_since_outage", outageFailures,
			)
		}
		retryAt = time.Time{}
		retryDelay = 0
		outageDropped = 0
		outageFailures = 0
		lastOutageWarning = time.Time{}
	}
	return stats
}

func (c *Client) get(ctx context.Context, path string, output any) error {
	return c.request(ctx, http.MethodGet, path, nil, output)
}

func (c *Client) request(ctx context.Context, method, path string, body []byte, output any) error {
	parsed, err := url.Parse(path)
	if err != nil {
		return err
	}
	requestURL := (&url.URL{Scheme: "http", Host: "unix", Path: parsed.Path, RawQuery: parsed.RawQuery}).String()
	req, err := http.NewRequestWithContext(ctx, method, requestURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	if len(body) > 0 {
		req.Header.Set("Content-Type", "text/plain")
	}
	response, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("local API request: %w", err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 16<<20))
	if err != nil {
		return fmt.Errorf("read local API response: %w", err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var apiError struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(responseBody, &apiError) == nil && apiError.Error != "" {
			return &localAPIStatusError{code: response.StatusCode, message: "local API: " + apiError.Error}
		}
		return &localAPIStatusError{code: response.StatusCode, message: "local API returned " + response.Status}
	}
	if output != nil && len(responseBody) > 0 {
		if err := json.Unmarshal(responseBody, output); err != nil {
			return fmt.Errorf("decode local API response: %w", err)
		}
	}
	return nil
}
