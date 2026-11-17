package managed

import (
	"encoding/json"
	"testing"
)

func TestBatchUsesIndependentContiguousDeliverySequence(t *testing.T) {
	batch := Batch{EnrollmentID: "enrollment", SpoolID: "spool", Records: []Record{
		{Sequence: 10, Kind: RecordKindEvent, ID: "event-1", Payload: json.RawMessage(`{"sequence":1000}`)},
		{Sequence: 11, Kind: RecordKindEvent, ID: "event-2", Payload: json.RawMessage(`{"sequence":1101}`)},
	}}
	if err := batch.Validate(); err != nil {
		t.Fatalf("source sequence gaps should not block delivery: %v", err)
	}
	batch.Records[1].Sequence = 12
	if err := batch.Validate(); err == nil {
		t.Fatal("delivery gap accepted")
	}
}

func TestRecordBoundsAndKinds(t *testing.T) {
	for _, record := range []Record{
		{Sequence: 0, Kind: RecordKindEvent, ID: "id", Payload: json.RawMessage(`{}`)},
		{Sequence: 1, Kind: "command", ID: "id", Payload: json.RawMessage(`{}`)},
		{Sequence: 1, Kind: RecordKindAudit, ID: "id", Payload: json.RawMessage(`null`)},
		{Sequence: 1, Kind: RecordKindAudit, ID: "id", Payload: json.RawMessage(`[]`)},
		{Sequence: 1, Kind: RecordKindAudit, ID: "id", Payload: make([]byte, MaxRecordBytes+1)},
	} {
		if record.Validate() == nil {
			t.Fatal("invalid record accepted")
		}
	}
}
