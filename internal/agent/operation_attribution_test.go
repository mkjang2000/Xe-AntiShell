package agent

import (
	"context"
	"testing"
	"time"

	"xe-antishell/internal/config"
	"xe-antishell/internal/model"
)

func TestOperationAttributesCompatibleBootstrapWithoutBorrowingReusedPID(t *testing.T) {
	for _, name := range []string{"bootstrap", "live_lookup", "different_execution", "newer_process"} {
		t.Run(name, func(t *testing.T) {
			service, store := newTestService(t, config.CollectorDisabled, nil)
			defer store.Close()
			event := operationFixture(t, "file.write", time.Now().UTC())
			current := event.Process
			current.Key, current.ExecID = "bootstrap", ""
			current.StartTime = event.Process.StartTime.Add(-time.Second)
			current.OriginService = "custom-web.service"
			want := current.OriginService
			switch name {
			case "live_lookup":
				current.OriginService = ""
				service.processSource = staticProcessSource{origin: want}
			case "different_execution":
				current.ExecID = "different-execution"
				want = ""
			case "newer_process":
				current.StartTime = event.Process.StartTime.Add(time.Second)
				want = ""
			}
			service.lineage.Restore([]model.Process{current})
			if err := service.observeOperationContext(context.Background(), &event); err != nil {
				t.Fatal(err)
			}
			if event.Process.OriginService != want {
				t.Fatalf("attribution=%q, want %q", event.Process.OriginService, want)
			}
		})
	}
}
