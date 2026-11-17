package updates

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestAbandonedPrivateTemporariesCleanWithoutDeletingOtherFiles(t *testing.T) {
	m, c, id, inventory, _, _ := fixture(t)
	if err := m.Store.Prepare(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{".download-crashed", ".job-crashed", "operator-notes"} {
		if err := os.WriteFile(filepath.Join(m.Store.Directory, name), []byte("public fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	c.plan = nil
	if err := m.Once(context.Background(), c, id, inventory); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{".download-crashed", ".job-crashed"} {
		if _, err := os.Stat(filepath.Join(m.Store.Directory, name)); !os.IsNotExist(err) {
			t.Fatal("abandoned temporary retained")
		}
	}
	if _, err := os.Stat(filepath.Join(m.Store.Directory, "operator-notes")); err != nil {
		t.Fatal("unrelated file removed")
	}
}

func TestJobHardLinkAndDirectoryPermissionsRejected(t *testing.T) {
	m, c, id, inventory, _, _ := fixture(t)
	if err := m.Once(context.Background(), c, id, inventory); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(m.Store.Directory, "job.json"), filepath.Join(t.TempDir(), "linked-job")); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Store.Read(); err == nil {
		t.Fatal("hard-linked journal accepted")
	}
	if err := os.Chmod(m.Store.Directory, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := m.Store.Prepare(); err == nil {
		t.Fatal("non-private directory accepted")
	}
}
