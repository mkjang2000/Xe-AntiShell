package procfs

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"xe-antishell/internal/model"
)

func TestSystemServiceUnitRequiresHostManagerMembership(t *testing.T) {
	for name, want := range map[string]string{
		"0::/system.slice/nginx.service":                                            "nginx.service",
		"0::/system.slice/system-pm2.slice/pm2@deploy.service":                      "pm2@deploy.service",
		"1:cpu:/system.slice/nginx.service\n0::/system.slice/pm2@deploy.service":    "pm2@deploy.service",
		"0::/user.slice/user-1000.slice/user@1000.service/app.slice/nginx.service":  "",
		"0::/system.slice/delegated.service/nginx.service":                          "",
		"0::/system.slice/docker.service/docker-1.scope/system.slice/nginx.service": "",
		"0::/machine.slice/machine-system.scope/system.slice/nginx.service":         "",
		"0::/system.slice/nginx.service/unowned":                                    "",
		"1:cpu:/system.slice/nginx.service":                                         "",
		"0::/system.slice/nginx.service\n0::/system.slice/pm2.service":              "",
		"0::/system.slice/nginx.scope":                                              "",
	} {
		if got := systemServiceUnit(name); got != want {
			t.Errorf("unit in %q = %q, want %q", name, got, want)
		}
	}
}

func TestSystemServiceRejectsRecycledPIDWrongExecutableAndBoot(t *testing.T) {
	root := t.TempDir()
	bootDir := filepath.Join(root, "sys/kernel/random")
	if err := os.MkdirAll(bootDir, 0700); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, filepath.Join(bootDir, "boot_id"), "test-boot\n")
	writeFixture(t, filepath.Join(root, "uptime"), "1000.00 1234.00\n")
	writeProcessFixture(t, root, 10, 1, 99800, "/bin/bash", "0 0 0 0", "0 0 0 0", "0::/system.slice/nginx.service\n")
	s := New(root)
	now := time.Now()
	s.now = func() time.Time { return now }
	base := model.Event{BootID: "test-boot", EventTime: now.Add(-time.Second), Process: model.Process{PID: 10, Exe: "/bin/bash"}}
	if got, err := s.SystemService(context.Background(), base); err != nil || got != "nginx.service" {
		t.Fatalf("direct unit = %q, %v", got, err)
	}
	for _, mutate := range []func(*model.Event){
		func(e *model.Event) { e.EventTime = now.Add(-3 * time.Second) },
		func(e *model.Event) { e.EventTime = now.Add(-2 * time.Second) }, // overlapping procfs clock resolution
		func(e *model.Event) { e.Process.Exe = "/bin/old" },
		func(e *model.Event) { e.BootID = "old-boot" },
		func(e *model.Event) { e.Process.PID = 99 },
	} {
		event := base
		mutate(&event)
		if _, err := s.SystemService(context.Background(), event); err == nil {
			t.Fatal("unverified process matched a host unit")
		}
	}
}
