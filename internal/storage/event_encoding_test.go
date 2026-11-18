package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"xe-antishell/internal/model"
)

func eventEncodingFixture(ancestorCount int) model.Event {
	event := testEvent("encoding-fixture", 1, time.Date(2026, 11, 18, 0, 0, 0, 123456789, time.UTC))
	id := uint32(1000)
	host, level := true, int32(0)
	caps := make([]string, 41)
	for index := range caps {
		caps[index] = fmt.Sprintf("CAP_FUTURE_%02d", index)
	}
	snapshot := &model.CredentialSnapshot{
		UID: &id, EUID: &id, GID: &id, EGID: &id, SUID: &id, SGID: &id, FSUID: &id, FSGID: &id,
		Capabilities:  &model.CredentialCapabilities{Effective: caps, Permitted: append([]string(nil), caps...), Inheritable: []string{}},
		UserNamespace: &model.UserNamespace{Inum: 4026531837, IsHost: &host, Level: &level},
	}
	event.Process.Credentials = snapshot
	event.Process.ExecPrivileges = &model.ExecPrivileges{SetUID: &id, Reasons: []string{"PRIVILEGES_RAISED_EXEC_FILE_SETUID"}}
	event.Process.Exe, event.Process.Argv = "/srv/한글/<>&/프로그램", []string{"문자😀", "<>&", "\u2028\u2029", "quote\"backslash\\"}
	event.Ancestors = make([]model.Process, ancestorCount)
	for index := range event.Ancestors {
		process := testProcess(fmt.Sprintf("encoding-parent-%d", index), 200+index, event.EventTime.Add(-time.Minute))
		process.Credentials = snapshot.Clone()
		event.Ancestors[index] = process
	}
	return event
}

func TestStoredEventBundleBytesMatchProtocolSerializer(t *testing.T) {
	base := eventEncodingFixture(3)
	zero := int64(0)
	cases := []struct {
		name  string
		event model.Event
	}{{"nested-credentials-unicode-html", base}}
	for _, raw := range []string{` { "html":"<>&", "unicode":"한글😀", "n":1e+05 } `, "{\"line\":\"\u2028\u2029\",\"duplicate\":1,\"duplicate\":2}", `null`, `[true,{"escaped":"\\\""}]`} {
		event := base
		event.RawJSON = json.RawMessage(raw)
		cases = append(cases, struct {
			name  string
			event model.Event
		}{fmt.Sprintf("raw-%d", len(cases)), event})
	}
	for _, kind := range []string{"process.exec_observation", "file.write", "network.connect", "process.credential_change"} {
		event := base
		event.Type = kind
		switch kind {
		case "process.exec_observation":
			event.Execution = &model.ExecutionObservation{Runtime: "python", Mode: "inline", Evidence: "exact_argv", Option: "-c"}
		case "file.write":
			event.File = &model.FileObservation{Path: "/srv/한글/<>&", Operation: "write", Outcome: "no_data", ReturnValue: &zero, PolicyName: "xeas-file-write-v1", Function: "vfs_write"}
		case "network.connect":
			event.Network = &model.NetworkObservation{Operation: "connect", Protocol: "tcp", Family: "ipv6", DestinationAddress: "2001:db8::1", DestinationPort: 443, Outcome: "initiated", ReturnValue: &zero, PolicyName: "xeas-network-connect-v1", Function: "tcp_v6_connect"}
		case "process.credential_change":
			event.Credential = &model.CredentialObservation{Before: event.Process.Credentials.Clone(), After: event.Process.Credentials.Clone(), TGID: event.Process.PID, TID: event.Process.PID, TaskStartTimeNS: math.MaxUint64, Evidence: model.CredentialEvidence, PolicyName: model.CredentialPolicyName, Function: "commit_creds", ReturnValue: &zero, Outcome: "applied"}
		}
		cases = append(cases, struct {
			name  string
			event model.Event
		}{kind, event})
	}
	for _, item := range cases {
		for _, findingKind := range []string{"nil", "empty", "present"} {
			t.Run(item.name+"/"+findingKind, func(t *testing.T) {
				store := enrolledTestStore(t)
				event := item.event
				var findings []model.Finding
				if findingKind == "empty" {
					findings = []model.Finding{}
				} else if findingKind == "present" {
					finding := managedTestFinding(event)
					finding.Summary = "한글😀 <>& \u2028\u2029"
					findings = []model.Finding{finding}
				}
				wantEvent, err := json.Marshal(event)
				if err != nil {
					t.Fatal(err)
				}
				want, err := json.Marshal(managed.EventBundle{Event: event, Findings: findings})
				if err != nil {
					t.Fatal(err)
				}
				if err := store.PersistObservation(context.Background(), event, findings); err != nil {
					t.Fatal(err)
				}
				var stored []byte
				if err := store.db.QueryRow("SELECT event_json FROM events WHERE event_id=?", event.ID).Scan(&stored); err != nil || !bytes.Equal(stored, wantEvent) {
					t.Fatalf("event encoding changed: %v", err)
				}
				batch, err := store.DeliveryBatch(context.Background(), 1)
				if err != nil || len(batch.Records) != 1 || !bytes.Equal(batch.Records[0].Payload, want) {
					t.Fatalf("bundle differs from canonical protocol bytes: %v", err)
				}
				var decoded managed.EventBundle
				if err := json.Unmarshal(batch.Records[0].Payload, &decoded); err != nil || (event.Credential != nil && decoded.Event.Credential.TaskStartTimeNS != math.MaxUint64) {
					t.Fatalf("typed evidence or full uint64 changed: %v", err)
				}
			})
		}
	}
}

func TestEventEncodingNeverCachesMutablePublicValues(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	event := eventEncodingFixture(1)
	want, _ := json.Marshal(event)
	inserted, first, err := store.saveEventResult(ctx, event)
	if err != nil || !inserted || !bytes.Equal(first, want) {
		t.Fatalf("fresh event encoding failed: %v", err)
	}
	event.Process.Argv[0] = "changed"
	*event.Process.Credentials.EUID = 0
	event.Ancestors[0].Exe = "/changed-parent"
	if !bytes.Equal(first, want) {
		t.Fatal("caller mutation changed an encoded event")
	}
	if inserted, err := store.SaveEventResult(ctx, event); inserted || !errors.Is(err, ErrConflict) {
		t.Fatalf("public save reused stale content after mutation: %v", err)
	}
	event.ID = "fresh-second-call"
	event.Sequence++
	inserted, second, err := store.saveEventResult(ctx, event)
	if err != nil || !inserted || bytes.Equal(first, second) {
		t.Fatalf("new call failed to encode current values: %v", err)
	}
	second[0] = '['
	if !bytes.Equal(first, want) {
		t.Fatal("separate calls share an encoding buffer")
	}
	stored, err := store.GetEvent(ctx, event.ID)
	if err != nil || stored.Process.Argv[0] != "changed" || *stored.Process.Credentials.EUID != 0 || stored.Ancestors[0].Exe != "/changed-parent" {
		t.Fatalf("fresh encoding was not durable or borrowed the returned buffer: %v", err)
	}
}

func TestEventEncodingKeepsPublicValidationAndErrorOrder(t *testing.T) {
	store, _ := openTestStore(t)
	for _, item := range []struct {
		name string
		edit func(*model.Event)
		want string
	}{
		{"ID", func(e *model.Event) { e.ID = "" }, "storage: event ID is required"},
		{"schema", func(e *model.Event) { e.SchemaVersion = "" }, "storage: event schema version is required"},
		{"type", func(e *model.Event) { e.Type = "" }, "storage: event type is required"},
		{"time", func(e *model.Event) { e.EventTime = time.Time{} }, "storage: event and ingest times are required"},
		{"sequence", func(e *model.Event) { e.Sequence = math.MaxUint64 }, "storage: event sequence exceeds SQLite integer range"},
	} {
		t.Run(item.name, func(t *testing.T) {
			event := eventEncodingFixture(0)
			event.RawJSON = json.RawMessage(`{`)
			item.edit(&event)
			if inserted, err := store.SaveEventResult(context.Background(), event); inserted || err == nil || err.Error() != item.want {
				t.Fatalf("validation order changed: %v", err)
			}
		})
	}
	for _, kind := range []string{"raw", "time"} {
		event := eventEncodingFixture(0)
		if kind == "raw" {
			event.RawJSON = json.RawMessage(`{`)
		} else {
			event.EventTime = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
		}
		inserted, err := store.SaveEventResult(context.Background(), event)
		var marshalError *json.MarshalerError
		if inserted || err == nil || !strings.HasPrefix(err.Error(), `storage: encode event "encoding-fixture": `) || !errors.As(err, &marshalError) {
			t.Fatalf("encoding error lost its original wrapping: %v", err)
		}
	}
}

func TestEventBundleEncodingKeepsFindingErrors(t *testing.T) {
	event := eventEncodingFixture(0)
	body, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"non-finite-confidence", "invalid-time"} {
		finding := managedTestFinding(event)
		if kind == "non-finite-confidence" {
			finding.Confidence = math.NaN()
		} else {
			finding.CreatedAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
		}
		findings := []model.Finding{finding}
		_, want := json.Marshal(managed.EventBundle{Event: event, Findings: findings})
		payload, got := marshalEventBundle(body, findings)
		if got == nil || want == nil || got.Error() != want.Error() || fmt.Sprintf("%T", got) != fmt.Sprintf("%T", want) || payload != nil {
			t.Fatalf("finding encoding error differs from protocol: got=%v want=%v", got, want)
		}
	}
}
