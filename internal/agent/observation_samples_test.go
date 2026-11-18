package agent

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"xe-antishell/internal/collector"
	"xe-antishell/internal/config"
	"xe-antishell/internal/model"
	"xe-antishell/internal/storage"
)

const sampleProbeExecutable = "/usr/bin/python3"

type sampleProbe struct {
	hostID    string
	webParent bool
	at        time.Time
	identity  string
	pid       int
	start     time.Time
	path      string
	address   string
	result    *int64
}

// Build source records at the Tetragon adapter boundary. Service membership
// is supplied separately by process bootstrap, just as for a live source.
func (p sampleProbe) normalize(t *testing.T, received time.Time) model.Event {
	t.Helper()
	body := map[string]any{
		"action": "KPROBE_ACTION_POST",
		"process": map[string]any{
			"pid": p.pid, "exec_id": p.identity, "start_time": p.start,
			"binary": sampleProbeExecutable, "uid": 1000,
			"arguments": "private sample argument",
		},
	}
	if p.webParent {
		body["parent"] = map[string]any{"exec_id": "ancestry-nginx", "pid": 898, "binary": "/usr/sbin/nginx", "start_time": p.start.Add(-time.Hour)}
	}
	resultField := "long_arg"
	if p.path != "" {
		body["policy_name"], body["function_name"] = "xeas-file-write-v1", "vfs_write"
		body["args"] = []any{map[string]any{"label": "target", "file_arg": map[string]any{"path": p.path}}}
	} else {
		resultField = "int_arg"
		body["policy_name"], body["function_name"] = "xeas-network-connect-v1", "tcp_v4_connect"
		body["args"] = []any{map[string]any{"label": "destination", "sockaddr_arg": map[string]any{"family": "AF_INET", "addr": p.address, "port": 443}}}
	}
	if p.result != nil {
		body["return"] = map[string]any{resultField: *p.result}
	}
	raw, err := json.Marshal(map[string]any{"time": p.at, "process_kprobe": body})
	if err != nil {
		t.Fatal(err)
	}
	host := p.hostID
	if host == "" {
		host = "host-test"
	}
	event, err := collector.NormalizeTetragonJSON(raw, received, collector.Metadata{HostID: host, BootID: "boot-test"})
	if err != nil {
		t.Fatal(err)
	}
	return event
}

func TestObservationSamplesFromTetragonForDeploymentUploadsAndAPI(t *testing.T) {
	const serviceName = "shop.service"
	const secondService = "billing.service"
	const protected = "/srv/shop"
	const allowed = "/srv/shop/var"
	s, store := newTestService(t, config.CollectorDisabled, func(c *config.Config) {
		c.Detection.WebServices = []string{serviceName, secondService}
		c.Detection.ExtendedProcessRules = true
	})
	defer store.Close()
	ctx := context.Background()
	start := time.Date(2026, 11, 17, 10, 0, 0, 0, time.UTC)
	bootstrap := func(key, service string, pid int) model.Process {
		return model.Process{Key: key, PID: pid, Exe: sampleProbeExecutable, OriginService: service, StartTime: start}
	}
	s.lineage.Restore([]model.Process{bootstrap("bootstrap-a", serviceName, 901), bootstrap("bootstrap-b", secondService, 902)})
	written, zero, failed := int64(384), int64(0), int64(-13)
	// Receive later source observations first. The same positive path under
	// the other service must not enter this service-specific review.
	tests := []struct {
		path, address   string
		result          *int64
		outcome, review string
	}{
		{path: "/srv/shop/app/releases/release.php", result: &written, outcome: "written", review: "protected_write_candidate"},
		{path: "/srv/shop/var/uploads/photo.jpg", result: &written, outcome: "written", review: "allowed_path"},
		{path: "/srv/shop/var/cache/catalog", result: &written, outcome: "written", review: "allowed_path"},
		{path: "/srv/shop/var-old/maintenance", result: &written, outcome: "written", review: "protected_write_candidate"},
		{path: "/srv/shop-old/release.php", result: &written, outcome: "written", review: "outside_protected_path"},
		{path: "/srv/shop/app/zero.php", result: &zero, outcome: "no_data", review: "unconfirmed_write"},
		{path: "/srv/shop/app/failed.php", result: &failed, outcome: "failed", review: "unconfirmed_write"},
		{path: "/srv/shop/app/missing.php", outcome: "unknown", review: "unconfirmed_write"},
		{address: "192.0.2.22", result: &zero, outcome: "initiated"},
		{address: "192.0.2.23", result: &failed, outcome: "failed"},
		{address: "192.0.2.24", outcome: "unknown"},
	}
	probes := make([]sampleProbe, len(tests))
	ids := make([]string, len(tests))
	persist := func(p sampleProbe, received time.Time) string {
		t.Helper()
		event := p.normalize(t, received)
		if err := s.processEvent(ctx, &event); err != nil {
			t.Fatal(err)
		}
		return event.ID
	}
	received := start.Add(time.Hour)
	for i := len(tests) - 1; i >= 0; i-- {
		tc := tests[i]
		probes[i] = sampleProbe{at: start.Add(time.Minute + time.Duration(i)*time.Second), start: start, identity: "shop-worker", pid: 901, path: tc.path, address: tc.address, result: tc.result}
		ids[i] = persist(probes[i], received)
	}
	if replayID := persist(probes[0], received.Add(time.Minute)); replayID != ids[0] {
		t.Fatal("retry changed evidence identity")
	}
	other := probes[0]
	other.identity, other.pid = "billing-worker", 902
	otherID := persist(other, received)

	// A delayed record from a previous execution at the same PID must not
	// borrow the current source's service label or become its write candidate.
	old := probes[0]
	old.start, old.at, old.identity = start.Add(-2*time.Hour), start.Add(-time.Hour), "previous-worker"
	unattributedID := persist(old, received)
	if _, err := store.GetEvent(ctx, unattributedID); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("unattributed operation passed web-origin retention: %v", err)
	}

	query := model.ObservationQuery{Service: serviceName, ProtectedDir: protected, AllowedDir: allowed, Limit: 100}
	report, err := s.Observations(ctx, query)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Samples) != len(tests) {
		t.Fatalf("samples duplicated, missing or cross-service: got %d want %d", len(report.Samples), len(tests))
	}
	for i, tc := range tests {
		row := report.Samples[len(tests)-1-i]
		if row.EventID != ids[i] || !row.EventTime.Equal(probes[i].at) || row.Outcome != tc.outcome || row.Service != serviceName {
			t.Errorf("row %d has wrong source identity, ordering, or outcome: %+v", i, row)
		}
		if (row.ReturnValue == nil) != (tc.result == nil) || row.ReturnValue != nil && tc.result != nil && *row.ReturnValue != *tc.result {
			t.Errorf("return value changed, sample %+v", row)
		}
		if tc.path != "" && (row.EventType != "file.write" || row.Path != tc.path) {
			t.Errorf("write metadata lost: %+v", row)
		}
		if tc.address != "" && (row.EventType != "network.connect" || row.DestinationAddress != tc.address || row.DestinationPort != 443) {
			t.Errorf("connect metadata lost: %+v", row)
		}
		if row.Review != tc.review {
			t.Errorf("review %q for %s %s, expected %q", row.Review, tc.path, tc.address, tc.review)
		}
	}
	report, err = s.Observations(ctx, model.ObservationQuery{Service: secondService, Limit: 1})
	if err != nil || len(report.Samples) != 1 || report.Samples[0].EventID != otherID || report.Samples[0].Review == "protected_write_candidate" {
		t.Fatalf("second service: %+v %v", report, err)
	}
	findings, err := store.ListFindings(ctx, storage.FindingFilter{Limit: 100})
	if err != nil || len(findings) != 0 {
		t.Fatalf("observation review created findings: %+v %v", findings, err)
	}
}

func TestObservationSamplesKeepUnknownServiceAfterProcessAttributionChanges(t *testing.T) {
	s, store := newTestService(t, config.CollectorDisabled, nil)
	defer store.Close()
	ctx := context.Background()
	start := time.Date(2026, 11, 17, 11, 0, 0, 0, time.UTC)
	n := int64(2)
	probe := sampleProbe{at: start.Add(time.Minute), start: start, identity: "worker-with-nginx-parent", pid: 921, webParent: true, path: "/srv/shop/index.php", result: &n}
	event := probe.normalize(t, start.Add(time.Hour))
	if err := s.processEvent(ctx, &event); err != nil {
		t.Fatal(err)
	}
	p, err := store.GetProcess(ctx, event.Process.Key)
	if err != nil {
		t.Fatal(err)
	}
	if p.OriginService != "" {
		t.Fatalf("fixture fabricated a service label: %q", p.OriginService)
	}
	p.OriginService = "shop.service"
	if err := store.SaveProcess(ctx, event.BootID, p); err != nil {
		t.Fatal(err)
	}
	report, err := s.Observations(ctx, model.ObservationQuery{Service: "unknown"})
	if err != nil || len(report.Samples) != 1 || report.Samples[0].EventID != event.ID || report.Samples[0].Service != "unknown" || report.Samples[0].Review != "" {
		t.Fatalf("original observation lost unknown attribution: %+v %v", report, err)
	}
	report, err = s.Observations(ctx, model.ObservationQuery{Service: "shop.service", ProtectedDir: "/srv/shop"})
	if err != nil || len(report.Samples) != 0 {
		t.Fatalf("historical write borrowed a later service label: %+v %v", report, err)
	}
	if _, err = s.Observations(ctx, model.ObservationQuery{Service: "unknown", ProtectedDir: "/srv/shop"}); err == nil {
		t.Fatal("path review accepted an unattributed service")
	}
}
