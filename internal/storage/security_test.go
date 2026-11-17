package storage

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenRejectsSymlinkDatabasePath(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("do not replace"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "sentineld.db")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), link); err == nil {
		t.Fatal("Open() accepted a symlink database path")
	}
	contents, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "do not replace" {
		t.Fatalf("symlink target changed: %q", contents)
	}
}
