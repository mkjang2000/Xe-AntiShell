package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"xe-antishell/internal/config"
	"xe-antishell/internal/hostmetrics"
	"xe-antishell/internal/model"
)

type independentCentral struct {
	binary, state, agentAddress, adminAddress, operator string
	ca                                                  []byte
	http                                                *http.Client
	command                                             *exec.Cmd
	done                                                chan error
}

func newIndependentCentral(t *testing.T, ctx context.Context, binary string) *independentCentral {
	t.Helper()
	c := &independentCentral{binary: binary, state: filepath.Join(t.TempDir(), "central"), http: &http.Client{Timeout: time.Second}}
	var listeners []net.Listener
	for range 2 {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		listeners = append(listeners, listener)
		t.Cleanup(func() { _ = listener.Close() })
	}
	c.agentAddress, c.adminAddress = listeners[0].Addr().String(), listeners[1].Addr().String()
	for _, listener := range listeners {
		_ = listener.Close()
	}
	c.run(t, ctx, "init", "--state-dir", c.state, "--hosts", "127.0.0.1")
	c.ca = readCentralTestFile(t, filepath.Join(c.state, "ca.pem"))
	c.operator = strings.TrimSpace(string(readCentralTestFile(t, filepath.Join(c.state, "operator-token"))))
	t.Cleanup(func() { c.stop(t); c.http.CloseIdleConnections() })
	return c
}

func readCentralTestFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("cannot read isolated central fixture file")
	}
	return data
}

func (c *independentCentral) run(t *testing.T, parent context.Context, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, c.binary, args...)
	command.Stdout, command.Stderr = io.Discard, io.Discard
	if err := command.Run(); err != nil {
		t.Fatalf("isolated central %s failed: %v", args[0], err)
	}
}

func (c *independentCentral) start(t *testing.T, ctx context.Context) {
	t.Helper()
	c.command = exec.Command(c.binary, "serve", "--state-dir", c.state, "--listen", c.agentAddress, "--admin-listen", c.adminAddress)
	c.command.Stdout, c.command.Stderr = io.Discard, io.Discard
	if err := c.command.Start(); err != nil {
		t.Fatalf("start isolated central: %v", err)
	}
	c.done = make(chan error, 1)
	command, done := c.command, c.done
	go func() { done <- command.Wait() }()
	waitFor(t, func() bool { return c.request(ctx, http.MethodGet, "/admin/agents", nil, nil) == nil })
}

func (c *independentCentral) stop(t *testing.T) {
	t.Helper()
	if c.command == nil || c.command.Process == nil {
		return
	}
	command, done := c.command, c.done
	c.command = nil
	_ = command.Process.Signal(syscall.SIGTERM)
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("isolated central exited unexpectedly: %v", err)
		}
	case <-time.After(6 * time.Second):
		_ = command.Process.Kill()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("isolated central child did not exit")
		}
		t.Error("isolated central graceful shutdown timed out")
	}
}

func (c *independentCentral) request(ctx context.Context, method, path string, input, output any) error {
	body, err := json.Marshal(input)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, method, "http://"+c.adminAddress+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+c.operator)
	request.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("central API status %d", response.StatusCode)
	}
	if output != nil {
		return json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(output)
	}
	_, err = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
	return err
}

func awaitIndependentCentral(t *testing.T, parent context.Context, stage string, condition func() bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 25*time.Second)
	defer cancel()
	for !condition() {
		select {
		case <-ctx.Done():
			t.Fatalf("%s exceeded its deadline", stage)
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func TestIndependentCentralWithMultipleAgents(t *testing.T) {
	binary := os.Getenv("XEAS_CENTRAL_TEST_BINARY")
	if binary == "" {
		t.Skip("set XEAS_CENTRAL_TEST_BINARY to test the independent central component")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
	defer cancel()
	central := newIndependentCentral(t, ctx, binary)
	central.start(t, ctx)
	services := make([]*Service, 2)
	enrollments := make([]string, 2)
	for i, id := range []string{"pilot-agent-a", "pilot-agent-b"} {
		service, store := newTestService(t, config.CollectorDisabled, func(cfg *config.Config) { cfg.Agent.ID = id })
		// All process and resource sources are synthetic, including early heartbeats.
		service.metrics = hostmetrics.New(t.TempDir(), t.TempDir())
		t.Cleanup(func() { shutdownService(t, service); _ = store.Close() })
		startService(t, service)
		services[i] = service
		tokenFile := filepath.Join(t.TempDir(), "enrollment-token")
		central.run(t, ctx, "enrollment-token", "--state-dir", central.state, "--agent-id", id, "--output-file", tokenFile)
		recovery, err := managed.NewChallenge()
		if err != nil {
			t.Fatal("create test recovery credential")
		}
		if _, err := service.EnrollWithRecovery(ctx, "https://"+central.agentAddress, id, central.ca, strings.TrimSpace(string(readCentralTestFile(t, tokenFile))), recovery); err != nil {
			t.Fatalf("enroll synthetic agent: %v", err)
		}
		status, err := service.ManagedStatus(ctx)
		if err != nil || !status.Enrolled || status.AgentID != id {
			t.Fatal("agent enrollment was not persisted")
		}
		enrollments[i] = status.EnrollmentID
		policy := managed.DefaultPolicy(id, status.EnrollmentID, 1, time.Now().UTC())
		policy.Detection.WebServices = []string{id + "-web.service"}
		policy.Monitoring = managed.MonitoringPolicy{Enabled: false, SampleIntervalSeconds: 5, ProcessLimit: 1}
		if err := central.request(ctx, http.MethodPost, "/admin/policy", policy, nil); err != nil {
			t.Fatalf("assign observation policy: %v", err)
		}
	}
	if enrollments[0] == "" || enrollments[0] == enrollments[1] {
		t.Fatal("agent enrollments are not independent")
	}
	for _, service := range services {
		awaitIndependentCentral(t, ctx, "policy activation", func() bool {
			status, err := service.ManagedStatus(ctx)
			return err == nil && status.Policy.ActiveRevision == 1 && status.Policy.Result == "applied"
		})
	}
	submit := func(eventID string) {
		for _, service := range services {
			event := model.Event{ID: eventID, Type: "process.exec", Source: "replay", EventTime: time.Now().UTC(),
				Process: model.Process{PID: 777, Exe: "/bin/bash", EUID: 1000, OriginService: service.config.Agent.ID + "-web.service"}}
			if err := service.Submit(ctx, event); err != nil {
				t.Fatal("submit synthetic process metadata")
			}
		}
	}
	submit("shared-online")
	awaitIndependentCentral(t, ctx, "initial delivery and heartbeats", func() bool {
		var agents []struct {
			ID         string            `json:"agent_id"`
			Enrollment string            `json:"enrollment_id"`
			Heartbeat  managed.Heartbeat `json:"heartbeat"`
		}
		if central.request(ctx, http.MethodGet, "/admin/agents", nil, &agents) != nil || len(agents) != 2 {
			return false
		}
		for i, agent := range agents {
			if agent.ID != services[i].config.Agent.ID || agent.Enrollment != enrollments[i] || agent.Heartbeat.AgentID != agent.ID || agent.Heartbeat.EnrollmentID != agent.Enrollment || agent.Heartbeat.PolicyStatus.ActiveRevision != 1 {
				return false
			}
			status, err := services[i].ManagedStatus(ctx)
			if err != nil || status.Delivery.Pending != 0 || status.Delivery.Acknowledged != 1 {
				return false
			}
		}
		return true
	})
	central.stop(t)
	submit("shared-offline")
	backlogs := make([]managed.Batch, len(services))
	for i, service := range services {
		waitFor(t, func() bool {
			findings, err := service.ListFindings(ctx, 10)
			status, statusErr := service.ManagedStatus(ctx)
			return err == nil && statusErr == nil && len(findings) == 2 && status.Delivery.Pending == 1
		})
		var err error
		backlogs[i], err = service.store.DeliveryBatch(ctx, 64)
		if err != nil || len(backlogs[i].Records) != 1 {
			t.Fatal("offline observation did not retain its delivery obligation")
		}
	}
	central.start(t, ctx) // Preserve the original state, CA, policy and listener ports.
	for i, service := range services {
		awaitIndependentCentral(t, ctx, "automatic backlog acknowledgement", func() bool {
			status, err := service.ManagedStatus(ctx)
			return err == nil && status.Delivery.Pending == 0 && status.Delivery.Acknowledged == 2 && status.Delivery.LostRecords == 0
		})
		client, _, err := service.managedConnection(ctx)
		if err != nil {
			t.Fatal("restore enrolled transport")
		}
		if ack, err := client.Ingest(ctx, backlogs[i]); err != nil || ack.Acknowledged != 2 {
			t.Fatal("previously acknowledged batch could not be safely replayed")
		}
		var rows []struct {
			AgentID string              `json:"agent_id"`
			ID      string              `json:"id"`
			Payload managed.EventBundle `json:"payload"`
		}
		if err := central.request(ctx, http.MethodGet, "/admin/history?kind=event_bundle&agent_id="+service.config.Agent.ID, nil, &rows); err != nil || len(rows) != 2 {
			t.Fatal("central history lost or duplicated synthetic observations")
		}
		seen := map[string]bool{}
		for _, row := range rows {
			bundle := row.Payload
			if seen[row.ID] || (row.ID != "shared-online" && row.ID != "shared-offline") || row.AgentID != service.config.Agent.ID || bundle.Event.HostID != row.AgentID || bundle.Event.ID != row.ID || len(bundle.Findings) != 1 {
				t.Fatal("central event bundles crossed agent boundaries or duplicated records")
			}
			finding := bundle.Findings[0]
			if finding.PolicyRevision != 1 || finding.ResponseDecision != "observe" || finding.OriginService != row.AgentID+"-web.service" || len(finding.EvidenceEventIDs) != 1 || finding.EvidenceEventIDs[0] != row.ID {
				t.Fatal("central bundle lost its observation policy or evidence association")
			}
			seen[row.ID] = true
		}
	}
}
