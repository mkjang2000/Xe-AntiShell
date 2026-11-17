package privileges

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeControl struct {
	policies      []policyState
	adds, deletes int
	failAdd       bool
	failList      bool
	listJSON      []byte
}

func readyPolicy() policyState {
	return policyState{Name: PolicyName, Domain: "static", State: "TP_STATE_ENABLED", Mode: "TP_MODE_MONITOR_ONLY", Hooks: []struct {
		State string `json:"state"`
	}{{State: "STATUS_LOADED"}}}
}
func (f *fakeControl) Run(_ context.Context, _ string, args ...string) ([]byte, error) {
	if len(args) < 4 {
		return nil, errors.New("missing fixed arguments")
	}
	switch args[3] {
	case "list":
		if f.failList {
			return nil, errors.New("list unavailable")
		}
		if f.listJSON != nil {
			return f.listJSON, nil
		}
		// Match Tetragon protojson: an empty repeated field is omitted. The
		// former {"policies":[]} fake concealed first-install failures.
		return json.Marshal(struct {
			Policies []policyState `json:"policies,omitempty"`
		}{Policies: f.policies})
	case "add":
		f.adds++
		if f.failAdd {
			return nil, errors.New("PRIVATE_OUTPUT")
		}
		f.policies = []policyState{readyPolicy()}
		return nil, nil
	case "delete":
		f.deletes++
		f.policies = nil
		return nil, nil
	}
	return nil, errors.New("arbitrary command attempted")
}
func testController(t *testing.T) (*Controller, *fakeControl) {
	t.Helper()
	r := &fakeControl{}
	c := New("/usr/bin/true", []string{"--server-address", "unix:///run/test.sock"}, filepath.Join(t.TempDir(), "owned"))
	c.status.Supported = true
	c.Runner = r
	c.checkCommand = func(string) error { return nil }
	c.checkSocket = func(string) error { return nil }
	c.checkParent = func(string) error { return nil }
	return c, r
}
func TestFixedPolicyOwnershipAndReconciliation(t *testing.T) {
	c, r := testController(t)
	ctx := context.Background()
	c.Reconcile(ctx, false)
	if r.adds+r.deletes != 0 {
		t.Fatal("disabled profile mutated collector")
	}
	c.Reconcile(ctx, true)
	s := c.Snapshot()
	if !s.Loaded || s.Error != "" || s.GenerationAt.IsZero() || r.adds != 1 {
		t.Fatalf("load failed: %#v", s)
	}
	b, e := os.ReadFile(filepath.Join(c.Directory, "policy.yaml"))
	if e != nil || string(b) != string(policy) {
		t.Fatal("staged policy is not embedded fixed bytes", e)
	}
	c.Reconcile(ctx, true)
	if r.adds != 1 {
		t.Fatal("idempotent reconciliation re-added policy")
	}
	r.policies = nil
	c.Reconcile(ctx, true)
	if !c.Snapshot().Loaded || r.adds != 2 {
		t.Fatal("missing owned policy was not reloaded")
	}
	c.Reconcile(ctx, false)
	if c.Snapshot().Loaded || r.deletes != 1 {
		t.Fatal("disabled policy remained active")
	}
	if _, e := os.Stat(filepath.Join(c.Directory, markerName)); !os.IsNotExist(e) {
		t.Fatal("ownership not removed", e)
	}
}
func TestForeignAndMalformedOwnershipFailClosed(t *testing.T) {
	c, r := testController(t)
	r.policies = []policyState{readyPolicy()}
	c.Reconcile(context.Background(), true)
	if c.Snapshot().Error != "foreign_policy" || r.adds+r.deletes != 0 {
		t.Fatal("foreign policy was replaced")
	}
	c, r = testController(t)
	if e := os.Mkdir(c.Directory, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(filepath.Join(t.TempDir(), "elsewhere"), filepath.Join(c.Directory, markerName)); e != nil {
		t.Fatal(e)
	}
	c.Reconcile(context.Background(), true)
	if c.Snapshot().Error != "ownership_invalid" || r.adds != 0 {
		t.Fatal("untrusted ownership accepted")
	}
}
func TestControllerFailureDoesNotInventActiveAndCanRetryIntent(t *testing.T) {
	c, r := testController(t)
	r.failAdd = true
	c.Reconcile(context.Background(), true)
	if c.Snapshot().Loaded || c.Snapshot().Error != "policy_add_failed" {
		t.Fatal("failed load invented activation")
	}
	if strings.Contains(c.Snapshot().Error, "PRIVATE") {
		t.Fatal("raw subprocess diagnostic leaked")
	}
	r.failAdd = false
	c.Reconcile(context.Background(), true)
	if !c.Snapshot().Loaded {
		t.Fatal("durable intent could not reconcile")
	}
	r.policies[0].Mode = "TP_MODE_ENFORCE"
	c.Reconcile(context.Background(), true)
	if c.Snapshot().Loaded || c.Snapshot().Error != "policy_not_ready" {
		t.Fatal("enforce policy treated as monitor-only")
	}
}
func TestFixedPolicyContainsOnlyReviewedMonitorHook(t *testing.T) {
	for _, text := range []string{"name: xeas-credential-change-v1", "call: commit_creds", "source: current_task", "resolve: cred", "action: Post", "value: monitor"} {
		if !strings.Contains(string(policy), text) {
			t.Fatal("fixed policy lost reviewed component", text)
		}
	}
	for _, text := range []string{"action: Sigkill", "action: Override", "rateLimit:", "host_ns"} {
		if strings.Contains(string(policy), text) {
			t.Fatal("policy gained unreviewed filtering or enforcement", text)
		}
	}
}

func TestControlRecoveryStartsNewReceiptEpoch(t *testing.T) {
	for _, fault := range []string{"policy", "list", "endpoint"} {
		t.Run(fault, func(t *testing.T) {
			c, r := testController(t)
			ctx := context.Background()
			c.Reconcile(ctx, true)
			first := c.Snapshot()
			if !first.Loaded {
				t.Fatal(first)
			}
			switch fault {
			case "policy":
				r.policies[0].Hooks[0].State = "STATUS_ERROR"
			case "list":
				r.failList = true
			case "endpoint":
				c.checkSocket = func(string) error { return errors.New("unavailable") }
			}
			c.Reconcile(ctx, true)
			if broken := c.Snapshot(); broken.Loaded || !broken.GenerationAt.After(first.GenerationAt) {
				t.Fatal("old loaded receipt epoch survived loss", broken)
			}
			r.policies = []policyState{readyPolicy()}
			r.failList = false
			c.checkSocket = func(string) error { return nil }
			resumedAt := time.Now().UTC()
			c.Reconcile(ctx, true)
			recovered := c.Snapshot()
			if !recovered.Loaded || recovered.GenerationAt.Before(resumedAt) {
				t.Fatal("recovery reused an old receipt epoch", recovered)
			}
			stable := recovered.GenerationAt
			c.Reconcile(ctx, true)
			if !c.Snapshot().GenerationAt.Equal(stable) {
				t.Fatal("healthy reconciliation invalidated current receipts")
			}
		})
	}
}
