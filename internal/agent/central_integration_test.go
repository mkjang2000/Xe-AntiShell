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

	contract "github.com/mkjang2000/Xe-AntiShell/protocol/integrity"
	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"xe-antishell/internal/config"
	"xe-antishell/internal/hostmetrics"
	"xe-antishell/internal/model"
	"xe-antishell/internal/storage"
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

type centralAgentSnapshot struct {
	ID         string            `json:"agent_id"`
	Enrollment string            `json:"enrollment_id"`
	Heartbeat  managed.Heartbeat `json:"heartbeat"`
}

func TestIndependentCentralAppliesApplicationPolicyRevision(t *testing.T) {
	binary := os.Getenv("XEAS_CENTRAL_TEST_BINARY")
	if binary == "" {
		t.Skip("set XEAS_CENTRAL_TEST_BINARY to test the independent central component")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	central := newIndependentCentral(t, ctx, binary)
	central.start(t, ctx)
	const id = "application-pilot"
	service, store := newTestService(t, config.CollectorDisabled, func(cfg *config.Config) {
		cfg.Agent.ID = id
	})
	service.metrics = hostmetrics.New(t.TempDir(), t.TempDir())
	t.Cleanup(func() { shutdownService(t, service); _ = store.Close() })
	startService(t, service)
	tokenFile := filepath.Join(t.TempDir(), "enrollment-token")
	central.run(t, ctx, "enrollment-token", "--state-dir", central.state, "--agent-id", id, "--output-file", tokenFile)
	recovery, err := managed.NewChallenge()
	if err != nil {
		t.Fatal("create test recovery credential")
	}
	if _, err := service.EnrollWithRecovery(ctx, "https://"+central.agentAddress, id, central.ca, strings.TrimSpace(string(readCentralTestFile(t, tokenFile))), recovery); err != nil {
		t.Fatal(err)
	}
	status, err := service.ManagedStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	heartbeat := func() managed.Heartbeat {
		var agents []centralAgentSnapshot
		if central.request(ctx, http.MethodGet, "/admin/agents", nil, &agents) == nil && len(agents) == 1 && agents[0].Enrollment == status.EnrollmentID {
			return agents[0].Heartbeat
		}
		return managed.Heartbeat{}
	}
	awaitIndependentCentral(t, ctx, "application capability", func() bool {
		report := heartbeat().Status.CapabilityReport
		return report != nil && report.Capabilities[managed.ApplicationPoliciesCapability].Details["contract"] == "1"
	})
	policy := managed.DefaultPolicy(id, status.EnrollmentID, 1, time.Now().UTC())
	policy.Monitoring = managed.MonitoringPolicy{Enabled: false, SampleIntervalSeconds: 5, ProcessLimit: 1}
	for _, entry := range []struct{ service, policyID, mode string }{
		{"nginx.service", "web-test", "would_block"}, {"pm2-deploy.service", "deploy-observe", "observe"},
	} {
		app := managed.ApplicationPolicy{
			Service: entry.service, PolicyID: entry.policyID, PolicyVersion: 1,
			Detection: managed.DetectionPolicy{Enabled: true, WebServices: []string{entry.service}, Shells: []string{"bash"}},
			Response:  policy.Response,
		}
		app.Response.Mode = entry.mode
		if entry.mode == "would_block" {
			app.Response.Action = "terminate"
			app.Response.RequiredCapabilities = []string{"observation.process_exec"}
		}
		policy.Applications = append(policy.Applications, app)
	}
	if err := central.request(ctx, http.MethodPost, "/admin/policy", policy, nil); err != nil {
		t.Fatalf("assign application policies: %v", err)
	}
	awaitIndependentCentral(t, ctx, "application revision and digest", func() bool {
		applied := heartbeat().PolicyStatus
		signed, err := store.Policy(ctx)
		if err != nil || applied.ActiveRevision != 1 || applied.Result != "applied" || len(signed.Policy.Applications) != 2 {
			return false
		}
		hash, err := contract.PolicyDigest(signed)
		return err == nil && hash != "" && applied.PolicySHA256 == hash &&
			signed.Policy.Applications[0].Response.Mode == "would_block" &&
			signed.Policy.Applications[1].Response.Mode == "observe"
	})

	policy.Revision, policy.Applications = 2, nil
	if err := central.request(ctx, http.MethodPost, "/admin/policy", policy, nil); err != nil {
		t.Fatalf("assign higher revision with legacy host policy: %v", err)
	}
	awaitIndependentCentral(t, ctx, "reapply host-only policy", func() bool {
		applied := heartbeat().PolicyStatus
		return applied.ActiveRevision == 2 && applied.Result == "applied" && applied.PolicySHA256 == ""
	})
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
		service, store := newTestService(t, config.CollectorDisabled, func(cfg *config.Config) {
			cfg.Agent.ID = id
			cfg.ServiceObservations = []config.ServiceObservationPolicy{observationScopeFixture(id + "-web.service")}
		})
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
		var agents []centralAgentSnapshot
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
	// Exercise a partial ACK and a separate final ACK after reconnecting.
	const offlineCount = 65
	expectedIDs := map[string]bool{"shared-online": true}
	for i := 0; i < offlineCount; i++ {
		id := fmt.Sprintf("shared-offline-%02d", i)
		expectedIDs[id] = true
		submit(id)
	}
	backlogs := make([]managed.Batch, len(services))
	offline := make([]storage.DeliveryStatus, len(services))
	recovered := make(map[string]storage.DeliveryStatus)
	for i, service := range services {
		awaitIndependentCentral(t, ctx, "first failed delivery while central is stopped", func() bool {
			findings, err := service.ListFindings(ctx, len(expectedIDs))
			status, statusErr := service.ManagedStatus(ctx)
			offline[i] = status.Delivery
			return err == nil && statusErr == nil && len(findings) == len(expectedIDs) && offline[i].Pending == offlineCount && offline[i].DisconnectAt != nil
		})
		if offline[i].FirstRecoveryACKAt != nil || offline[i].DrainedAt != nil || offline[i].OutageLostRecords != 0 {
			t.Fatal("outage reported recovery or loss before the first successful ACK")
		}
		var err error
		backlogs[i], err = service.store.DeliveryBatch(ctx, 64)
		if err != nil || len(backlogs[i].Records) != 64 {
			t.Fatal("offline observation did not retain its delivery obligation")
		}
		var firstBatchBytes int64
		for _, record := range backlogs[i].Records {
			firstBatchBytes += int64(len(record.Payload))
		}
		// The sender caps reads at 64 records. Recreate the final one from the
		// same immutable event and finding to replay its original ACK later.
		lastID := fmt.Sprintf("shared-offline-%02d", offlineCount-1)
		event, err := service.store.GetEvent(ctx, lastID)
		if err != nil {
			t.Fatal("read final buffered event")
		}
		findings, err := service.ListFindings(ctx, 1)
		if err != nil || len(findings) != 1 || len(findings[0].EvidenceEventIDs) != 1 || findings[0].EvidenceEventIDs[0] != lastID {
			t.Fatal("read final buffered finding")
		}
		body, err := json.Marshal(managed.EventBundle{Event: event, Findings: findings})
		if err != nil || offline[i].PendingBytes != firstBatchBytes+int64(len(body)) {
			t.Fatalf("outbox size %d differs from durable observation payloads", offline[i].PendingBytes)
		}
		backlogs[i].Records = []managed.Record{{Sequence: offlineCount + 1, Kind: managed.RecordKindEventBundle, ID: lastID, Payload: body}}
	}
	central.start(t, ctx) // Preserve the original state, CA, policy and listener ports.
	for i, service := range services {
		awaitIndependentCentral(t, ctx, "automatic backlog acknowledgement", func() bool {
			status, err := service.ManagedStatus(ctx)
			recovered[service.config.Agent.ID] = status.Delivery
			return err == nil && status.Delivery.Pending == 0 && status.Delivery.PendingBytes == 0 && status.Delivery.Acknowledged == offlineCount+1 && status.Delivery.FirstRecoveryACKAt != nil && status.Delivery.DrainedAt != nil
		})
		done := recovered[service.config.Agent.ID]
		if done.DisconnectAt == nil || !done.DisconnectAt.Equal(*offline[i].DisconnectAt) || done.FirstRecoveryACKAt.Before(*done.DisconnectAt) || !done.DrainedAt.After(*done.FirstRecoveryACKAt) || done.LostRecords != 0 || done.OutageLostRecords != 0 {
			t.Fatal("outage checkpoints lost their sequence or reported lost records")
		}
		t.Logf("%s backlog %d record(s), %d payload bytes, first ACK after %v, drained after %v, outage loss %d", service.config.Agent.ID, offline[i].Pending, offline[i].PendingBytes, done.FirstRecoveryACKAt.Sub(*done.DisconnectAt), done.DrainedAt.Sub(*done.DisconnectAt), done.OutageLostRecords)
		client, _, err := service.managedConnection(ctx)
		if err != nil {
			t.Fatal("restore enrolled transport")
		}
		if ack, err := client.Ingest(ctx, backlogs[i]); err != nil || ack.Acknowledged != offlineCount+1 {
			t.Fatal("previously acknowledged batch could not be safely replayed")
		}
		var rows []struct {
			AgentID string              `json:"agent_id"`
			ID      string              `json:"id"`
			Payload managed.EventBundle `json:"payload"`
		}
		if err := central.request(ctx, http.MethodGet, "/admin/history?kind=event_bundle&agent_id="+service.config.Agent.ID, nil, &rows); err != nil || len(rows) != len(expectedIDs) {
			t.Fatal("central history lost or duplicated synthetic observations")
		}
		seen := map[string]bool{}
		for _, row := range rows {
			bundle := row.Payload
			if seen[row.ID] || !expectedIDs[row.ID] || row.AgentID != service.config.Agent.ID || bundle.Event.HostID != row.AgentID || bundle.Event.ID != row.ID || len(bundle.Findings) != 1 {
				t.Fatal("central event bundles crossed agent boundaries or duplicated records")
			}
			finding := bundle.Findings[0]
			if finding.PolicyRevision != 1 || finding.ResponseDecision != "observe" || finding.OriginService != row.AgentID+"-web.service" || len(finding.EvidenceEventIDs) != 1 || finding.EvidenceEventIDs[0] != row.ID {
				t.Fatal("central bundle lost its observation policy or evidence association")
			}
			seen[row.ID] = true
		}
	}
	// The central component uses its own protocol binary. Exercise the data
	// that survives mTLS transport, central persistence, and the admin API.
	awaitIndependentCentral(t, ctx, "central heartbeat with recovered capacity for both agents", func() bool {
		var agents []centralAgentSnapshot
		if central.request(ctx, http.MethodGet, "/admin/agents", nil, &agents) != nil || len(agents) != len(recovered) {
			return false
		}
		for _, agent := range agents {
			want, ok := recovered[agent.ID]
			report := agent.Heartbeat.Status.CapabilityReport
			if !ok || report == nil || agent.Heartbeat.AgentID != agent.ID || agent.Enrollment != agent.Heartbeat.EnrollmentID {
				return false
			}
			details := report.Capabilities["storage.capacity"].Details
			if details["outage_lost_records"] != "0" || details["pending_records"] != "0" || details["pending_bytes"] != "0" {
				return false
			}
			for key, at := range map[string]*time.Time{"disconnect_at": want.DisconnectAt, "first_recovery_ack_at": want.FirstRecoveryACKAt, "drained_at": want.DrainedAt} {
				got, err := time.Parse(time.RFC3339Nano, details[key])
				if err != nil || !got.Equal(*at) {
					return false
				}
			}
		}
		return true
	})
	t.Run("service_observation_findings", func(t *testing.T) {
		for _, service := range services {
			verifyCentralServiceObservationFindings(t, ctx, central, service, recovered[service.config.Agent.ID].Acknowledged)
		}
	})
}
