package storage

import (
	"encoding/json"
	"testing"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"xe-antishell/internal/model"
)

var eventEncodingBenchmarkBytes []byte

// Include the event encoding needed by both paths; this measures only encoding,
// not SQLite, collection, the queue, transport or total Agent CPU.
func BenchmarkStoredEventBundleEncoding(b *testing.B) {
	for _, item := range []struct {
		name  string
		event model.Event
	}{{"Plain", testEvent("encoding-plain", 1, eventEncodingFixture(0).EventTime)}, {"Credentials4Ancestors", eventEncodingFixture(4)}, {"Credentials16Ancestors", eventEncodingFixture(16)}} {
		findings := []model.Finding{managedTestFinding(item.event)}
		for _, reuse := range []bool{false, true} {
			name := "ProtocolTwice"
			if reuse {
				name = "ReuseStoredEvent"
			}
			b.Run(item.name+"/"+name, func(b *testing.B) {
				b.ReportAllocs()
				for index := 0; index < b.N; index++ {
					body, err := json.Marshal(item.event)
					if err != nil {
						b.Fatal(err)
					}
					var payload []byte
					if reuse {
						payload, err = marshalEventBundle(body, findings)
					} else {
						payload, err = json.Marshal(managed.EventBundle{Event: item.event, Findings: findings})
					}
					if err != nil {
						b.Fatal(err)
					}
					eventEncodingBenchmarkBytes = payload
				}
			})
		}
	}
}
