package collector

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"testing"
	"time"

	"xe-antishell/internal/model"
)

func hotPathCaps() []string {
	set := make([]string, 0, len(tetragonCapabilityNames))
	for value := range tetragonCapabilityNames {
		set = append(set, value)
	}
	sort.Strings(set)
	return set
}

func hotPathSnapshot(euid uint32) map[string]any {
	snapshot := credentialSnapshotFixture(euid)
	snapshot["caps"] = map[string]any{"effective": hotPathCaps(), "permitted": hotPathCaps(), "inheritable": []string{}}
	return snapshot
}

func hotPathProcess(index int) map[string]any {
	return map[string]any{"exec_id": fmt.Sprintf("synthetic-exec-%d", index), "pid": 1000 + index, "tid": 1000 + index,
		"binary": "/usr/bin/synthetic-worker", "start_time": "2026-11-17T00:00:00Z", "uid": 0,
		"process_credentials": hotPathSnapshot(0), "arguments": observationPrivateFixture}
}

func hotPathFixture(kind string, depth int) []byte {
	var fixture map[string]any
	if kind == "exec" || kind == "exit" {
		process := hotPathProcess(0)
		body := map[string]any{"process": process}
		fixture = map[string]any{"time": "2026-11-17T00:00:01Z", "process_" + kind: body}
	} else {
		fixture = credentialFixture()
		probe := credentialProbe(fixture)
		probe["process"] = hotPathProcess(0)
		probe["args"].([]any)[0].(map[string]any)["process_credentials_arg"] = hotPathSnapshot(0)
		probe["data"].([]any)[0].(map[string]any)["process_credentials_arg"] = hotPathSnapshot(1000)
		probe["data"].([]any)[1].(map[string]any)["int_arg"] = 1000
		probe["data"].([]any)[3].(map[string]any)["int_arg"] = 1000
		delete(probe, "parent")
		delete(probe, "ancestors")
		if kind == "unchanged" {
			probe["args"].([]any)[0].(map[string]any)["process_credentials_arg"] = hotPathSnapshot(1000)
		} else if kind == "partial" {
			delete(credentialBefore(probe), "uid")
			delete(probe, "return")
		}
	}
	key := "process_kprobe"
	if kind == "exec" || kind == "exit" {
		key = "process_" + kind
	}
	body := fixture[key].(map[string]any)
	if depth > 0 {
		ancestors := make([]any, 0, depth)
		for index := 1; index <= depth; index++ {
			ancestor := hotPathProcess(index)
			if index < depth {
				ancestor["parent_exec_id"] = fmt.Sprintf("synthetic-exec-%d", index+1)
			}
			ancestors = append(ancestors, ancestor)
		}
		body["process"].(map[string]any)["parent_exec_id"] = "synthetic-exec-1"
		body["parent"], body["ancestors"] = ancestors[0], ancestors
	}
	raw, err := json.Marshal(fixture)
	if err != nil {
		panic("synthetic fixture encoding failed")
	}
	return raw
}

var hotPathCases = []struct {
	name, kind string
	depth      int
}{
	{"exec", "exec", 0}, {"exit", "exit", 0}, {"exec_ancestry8", "exec", 8},
	{"credential_unchanged", "unchanged", 0}, {"credential_unchanged_ancestry8", "unchanged", 8},
	{"credential_changed", "changed", 0}, {"credential_changed_ancestry8", "changed", 8}, {"credential_partial", "partial", 0},
}

func normalizeHotPath(raw []byte) (model.Event, error) {
	return NormalizeTetragonJSON(raw, time.Date(2026, 11, 17, 0, 0, 2, 0, time.UTC), Metadata{BootID: "synthetic-boot", HostID: "synthetic-host"})
}

func TestCollectorHotPathGolden(t *testing.T) {
	// SHA256 of the complete serialized normalized Event from Agent27. This
	// covers source IDs, all facts, nil/empty fields, privacy and parent context.
	expected := map[string]string{
		"exec":                         "75e0fbe6e6d6720a59a2684864fe972c813d714187af9173df0b727589e349f1",
		"exit":                         "28b103f3c39bf9d59364966560b4a36f7e52b4c61ab02a136ad4938de3404b0f",
		"exec_ancestry8":               "a5148eaf88a96732785fa741596ddaa270a6b311258af2c77d6abdc4590973fa",
		"credential_changed":           "46dbddf08ff4f9c1560b10376f1495685ad35f12ab12590409679597ce86c0e6",
		"credential_changed_ancestry8": "7faf33192f4deb0f1e140cdfa74ce4a9c690314247d6c4b8d176afcbfededa50",
		"credential_partial":           "ccf4552200a895be14cfd67a91d7dce19045e38a78815c2a5511c4ede2f5246d",
	}
	for _, test := range hotPathCases {
		t.Run(test.name, func(t *testing.T) {
			event, err := normalizeHotPath(hotPathFixture(test.kind, test.depth))
			if test.kind == "unchanged" {
				if !errors.Is(err, ErrUnsupportedEvent) {
					t.Fatalf("unchanged exclusion changed: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(event)
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(raw)
			digest := hex.EncodeToString(sum[:])
			if expected[test.name] == "" {
				t.Fatalf("baseline normalized digest: %s", digest)
			}
			if digest != expected[test.name] {
				t.Fatalf("normalized event changed: got %s", digest)
			}
		})
	}
}

func BenchmarkCollectorHotPath(b *testing.B) {
	for _, test := range hotPathCases {
		b.Run(test.name, func(b *testing.B) {
			raw := hotPathFixture(test.kind, test.depth)
			b.ReportAllocs()
			b.SetBytes(int64(len(raw)))
			b.ResetTimer()
			for index := 0; index < b.N; index++ {
				_, err := normalizeHotPath(raw)
				if test.kind == "unchanged" {
					if !errors.Is(err, ErrUnsupportedEvent) {
						b.Fatal("unchanged result changed")
					}
				} else if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
