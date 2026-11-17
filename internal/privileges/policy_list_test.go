package privileges

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPolicyListAcceptsUpstreamEmptyObjectAndExplicitArrays(t *testing.T) {
	for _, raw := range []string{`{}`, " \n{ \t }\n", `{"policies":[]}`} {
		policies, err := decodePolicyList([]byte(raw))
		if err != nil || policies == nil || len(policies) != 0 {
			t.Fatalf("normal empty list rejected: %q %#v %v", raw, policies, err)
		}
	}
	raw, err := json.Marshal(map[string]any{"policies": []policyState{readyPolicy()}})
	if err != nil {
		t.Fatal(err)
	}
	policies, err := decodePolicyList(raw)
	if err != nil || len(policies) != 1 || policies[0].Name != PolicyName || !ready(policies[0]) {
		t.Fatalf("populated policy list rejected: %#v %v", policies, err)
	}
}

func TestPolicyListRejectsMalformedUnknownAndAmbiguousResponses(t *testing.T) {
	invalid := []string{
		``, `null`, `[]`, `true`, `"{}"`, `{`, `{} {}`, `{} trailing`,
		`{"unexpected":[]}`, `{"policies":[],"unexpected":true}`,
		`{"policies":null}`, `{"policies":{}}`, `{"policies":"[]"}`, `{"policies":[null]}`, `{"policies":[{}]}`,
		`{"policies":[],"policies":[]}`, `{"policies":[],"\u0070olicies":[]}`,
		`{"policies":[{"name":"foreign","name":"xeas-credential-change-v1"}]}`,
		`{"policies":[{"name":"xeas-credential-change-v1","hook_statuses":[{"state":"STATUS_LOADED","state":"STATUS_LOADED"}]}]}`,
		`{"policies":[{"name":"xeas-credential-change-v1","unknown":{"a":1,"a":2}}]}`,
		`{"policies":[{"name":"xeas-credential-change-v1","name":null}]}`,
		`{"policies":[],}`, `{"policies":[{"name":false}]}`,
		`{"policies":[{"name":"nested","extra":` + strings.Repeat("[", 40) + `0` + strings.Repeat("]", 40) + `}]}`,
	}
	tooMany := make([]policyState, 257)
	for i := range tooMany {
		tooMany[i] = readyPolicy()
	}
	data, err := json.Marshal(map[string]any{"policies": tooMany})
	if err != nil {
		t.Fatal(err)
	}
	invalid = append(invalid, string(data))
	for _, raw := range invalid {
		t.Run(raw[:min(len(raw), 80)], func(t *testing.T) {
			if policies, err := decodePolicyList([]byte(raw)); err == nil {
				t.Fatalf("invalid response became a policy list: %q %#v", raw, policies)
			}
			c, r := testController(t)
			r.listJSON = []byte(raw)
			c.Reconcile(context.Background(), true)
			status := c.Snapshot()
			if status.Loaded || status.Error != "policy_list_failed" || r.adds+r.deletes != 0 {
				t.Fatalf("bad list triggered a mutation: %#v adds=%d deletes=%d", status, r.adds, r.deletes)
			}
			if _, err := os.Stat(filepath.Join(c.Directory, markerName)); !os.IsNotExist(err) {
				t.Fatal("bad list created ownership intent", err)
			}
		})
	}
}

func TestFirstPolicyReconciliationUsesActualEmptyCLIShape(t *testing.T) {
	c, r := testController(t)
	for _, policies := range [][]policyState{nil, {}} {
		r.policies = policies
		raw, err := r.Run(context.Background(), c.Command, "--server-address", c.Socket, "tracingpolicy", "list", "-o", "json")
		if err != nil || string(raw) != "{}" {
			t.Fatalf("fake empty output differs from upstream protojson: %q %v", raw, err)
		}
	}
	c.Reconcile(context.Background(), true)
	if status := c.Snapshot(); !status.Loaded || status.Error != "" || r.adds != 1 {
		t.Fatalf("first policy could not load from an empty list: %#v adds=%d", status, r.adds)
	}
	c.Reconcile(context.Background(), true)
	if r.adds != 1 {
		t.Fatal("healthy retry added a duplicate policy")
	}
}
