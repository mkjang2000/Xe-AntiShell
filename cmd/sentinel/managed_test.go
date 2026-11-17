package main

import (
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"testing"
)

func TestRecoveryFileIsSavedBeforeRequestAndReused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "recovery")
	first, err := prepareRecoveryFile(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := prepareRecoveryFile(path)
	if err != nil || first != second || len(first) != 43 {
		t.Fatal("recovery file was lost or replaced")
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("recovery credential permissions")
	}
	if err := os.WriteFile(path, []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareRecoveryFile(path); err == nil {
		t.Fatal("invalid existing recovery file accepted")
	}
}

func TestSecretFileRejectsSymlinksFIFOAndPublicPermissions(t *testing.T) {
	directory := t.TempDir()
	secret := filepath.Join(directory, "secret")
	if err := os.WriteFile(secret, []byte("not-a-real-token"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readBoundedFile(secret, 32, true); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(secret, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readBoundedFile(link, 32, true); err == nil {
		t.Fatal("symlink accepted")
	}
	fifo := filepath.Join(directory, "fifo")
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readBoundedFile(fifo, 32, true); err == nil {
		t.Fatal("FIFO accepted")
	}
	if err := os.Chmod(secret, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readBoundedFile(secret, 32, true); err == nil {
		t.Fatal("public secret accepted")
	}
}
