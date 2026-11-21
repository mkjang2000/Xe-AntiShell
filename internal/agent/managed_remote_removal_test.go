package agent

import (
	"context"
	"strings"
	"testing"

	"xe-antishell/internal/config"
)

func TestRemoteRemovalRejectsRootActionsWithoutHostSupport(t *testing.T) {
	for _, optIn := range []bool{false, true} {
		cfg := config.Default()
		cfg.Central.RemoteRemovalEnabled = optIn
		s := &Service{config: cfg}
		for _, action := range []string{"remote-removal-check", "removal-check"} {
			_, err := s.ManagementAction(context.Background(), action, []byte(`{"operation_id":"requested-a"}`))
			if err == nil || !strings.Contains(err.Error(), "not enabled") {
				t.Fatalf("unsupported host reached %s with opt-in %t: %v", action, optIn, err)
			}
		}
	}
}
