package procfs

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"xe-antishell/internal/model"
)

func TestSnapshotBuildsMinimalBootScopedLineage(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, filepath.Join(root, "stat"), "cpu 1 2 3 4\nbtime 1000\n")
	writeProcessFixture(t, root, 10, 1, 200, "/usr/sbin/nginx", "100 101 101 101", "200 201 201 201", "0::/system.slice/nginx.service\n")
	writeProcessFixture(t, root, 11, 10, 250, "/bin/bash", "100 101 101 101", "200 201 201 201", "0::/system.slice/nginx.service\n")
	if err := os.Mkdir(filepath.Join(root, "12"), 0o755); err != nil {
		t.Fatal(err)
	}

	snapshotter := New(root)
	snapshotter.now = func() time.Time { return time.Unix(2000, 0).UTC() }
	processes, err := snapshotter.Snapshot(context.Background(), "boot-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(processes) != 2 {
		t.Fatalf("snapshot length = %d, want 2: %#v", len(processes), processes)
	}
	byPID := make(map[int]model.Process)
	for _, process := range processes {
		byPID[process.PID] = process
	}
	parent, child := byPID[10], byPID[11]
	if parent.Key == "" || child.Key == "" || parent.Key == child.Key {
		t.Fatalf("invalid process keys: parent=%q child=%q", parent.Key, child.Key)
	}
	if child.ParentKey != parent.Key || !child.Complete || child.LineageConfidence != model.LineageInferred {
		t.Fatalf("child lineage = %#v", child)
	}
	if !child.StartTime.Equal(time.Unix(1002, 500_000_000).UTC()) {
		t.Fatalf("child start time = %s", child.StartTime)
	}
	if child.UID != 100 || child.EUID != 101 || child.GID != 200 || child.EGID != 201 {
		t.Fatalf("child credentials = %#v", child)
	}
	if parent.OriginService != "nginx.service" || child.OriginService != "nginx.service" {
		t.Fatalf("origin services: parent=%q child=%q", parent.OriginService, child.OriginService)
	}
	if len(child.Argv) != 0 || child.CWD != "" {
		t.Fatalf("snapshot retained unnecessary process data: %#v", child)
	}
}

func TestOriginServicePrefersLeafContainerScope(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "42")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, filepath.Join(dir, "cgroup"),
		"0::/system.slice/docker.service/docker-deadbeef.scope\n")
	origin, err := New(root).OriginService(context.Background(), 42)
	if err != nil {
		t.Fatal(err)
	}
	if origin != "docker-deadbeef.scope" {
		t.Fatalf("origin = %q", origin)
	}
}

func TestSnapshotRejectsMissingBootTime(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, filepath.Join(root, "stat"), "cpu 1 2 3 4\n")
	if _, err := New(root).Snapshot(context.Background(), "boot-a"); err == nil {
		t.Fatal("expected missing boot time error")
	}
}

func TestSnapshotHonorsCancellation(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, filepath.Join(root, "stat"), "btime 1000\n")
	if err := os.Mkdir(filepath.Join(root, "1"), 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := New(root).Snapshot(ctx, "boot-a"); err == nil {
		t.Fatal("expected cancellation error")
	}
}

func writeProcessFixture(t *testing.T, root string, pid, ppid int, startTicks uint64, exe, uid, gid, cgroup string) {
	t.Helper()
	dir := filepath.Join(root, stringInt(pid))
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	stat := stringInt(pid) + " (name with ) paren) S " + stringInt(ppid) +
		" 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 " + stringUint(startTicks) + " 0 0 0\n"
	writeFixture(t, filepath.Join(dir, "stat"), stat)
	writeFixture(t, filepath.Join(dir, "status"), "Name:\ttest\nUid:\t"+uid+"\nGid:\t"+gid+"\n")
	writeFixture(t, filepath.Join(dir, "cgroup"), cgroup)
	if err := os.Symlink(exe, filepath.Join(dir, "exe")); err != nil {
		t.Fatal(err)
	}
}

func writeFixture(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func stringInt(value int) string { return strconv.Itoa(value) }

func stringUint(value uint64) string { return strconv.FormatUint(value, 10) }
