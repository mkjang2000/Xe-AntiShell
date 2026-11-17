package model

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestObservationExtensionsPreserveLegacyJSON(t *testing.T) {
	body, err := json.Marshal(Event{Type: "process.exec"})
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(body, &fields); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"execution", "file", "network"} {
		if _, exists := fields[name]; exists {
			t.Fatalf("legacy event unexpectedly includes %s", name)
		}
	}
	var old Event
	if err = json.Unmarshal([]byte(`{"schema_version":"0.1","event_type":"process.exec","process":{"pid":7}}`), &old); err != nil {
		t.Fatal(err)
	}
	if old.Execution != nil || old.File != nil || old.Network != nil || old.Process.PID != 7 {
		t.Fatal("legacy event changed")
	}
}

func TestTypedObservationsRoundTrip(t *testing.T) {
	positive, zero, negative := int64(9), int64(0), int64(-13)
	cases := []Event{
		{Type: "process.exec_observation", Execution: &ExecutionObservation{Runtime: "python", Mode: "inline", Evidence: "tetragon_policy", Option: "-c", PolicyName: "xeas-exec-python-c-v1"}},
		{Type: "file.write", File: &FileObservation{Path: "/tmp/example", Operation: "write", Outcome: "written", ReturnValue: &positive, PolicyName: "xeas-file-write-v1", Function: "vfs_write"}},
		{Type: "network.connect", Network: &NetworkObservation{Operation: "connect", Protocol: "tcp", Family: "ipv4", DestinationAddress: "192.0.2.4", DestinationPort: 443, Outcome: "initiated", ReturnValue: &zero, PolicyName: "xeas-network-connect-v1", Function: "tcp_v4_connect"}},
		{Type: "network.connect", Network: &NetworkObservation{Operation: "connect", Protocol: "tcp", Family: "ipv6", DestinationAddress: "2001:db8::4", DestinationPort: 443, Outcome: "failed", ReturnValue: &negative, PolicyName: "xeas-network-connect-v1", Function: "tcp_v6_connect"}},
	}
	for _, want := range cases {
		t.Run(want.Type, func(t *testing.T) {
			data, err := json.Marshal(want)
			if err != nil {
				t.Fatal(err)
			}
			var got Event
			if err = json.Unmarshal(data, &got); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(want, got) {
				t.Fatal("typed observation changed during JSON round trip")
			}
		})
	}
}
