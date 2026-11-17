package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"xe-antishell/internal/webpanel"
)

func TestVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run([]string{"version"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(stdout.String()) != version {
		t.Fatalf("version output = %q", stdout.String())
	}
}

func TestInitAuthCreatesPrivateFilesWithoutPrintingPassword(t *testing.T) {
	directory := t.TempDir()
	authPath := filepath.Join(directory, "auth.json")
	passwordPath := filepath.Join(directory, "password.txt")
	var stdout, stderr bytes.Buffer
	err := run([]string{"init-auth", "--file", authPath, "--initial-password-file", passwordPath, "--username", "admin"}, &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	passwordBytes, err := os.ReadFile(passwordPath)
	if err != nil {
		t.Fatal(err)
	}
	password := strings.TrimSpace(string(passwordBytes))
	if password == "" || strings.Contains(stdout.String(), password) {
		t.Fatal("generated password was empty or printed")
	}
	credentials, err := webpanel.LoadCredentials(authPath)
	if err != nil {
		t.Fatal(err)
	}
	if !credentials.Verify("admin", password) {
		t.Fatal("generated password does not match auth file")
	}
	for _, path := range []string{authPath, passwordPath} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %04o", path, info.Mode().Perm())
		}
	}
	if err := run([]string{"init-auth", "--file", authPath, "--initial-password-file", passwordPath}, &stdout, &stderr); err == nil {
		t.Fatal("init-auth overwrote existing credentials")
	}
}

func TestServeRejectsUnsafePathsBeforeLoadingCredentials(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run([]string{"serve", "--socket", "relative.sock", "--auth-file", "/missing"}, &stdout, &stderr); err == nil {
		t.Fatal("relative socket path was accepted")
	}
	if err := run([]string{"serve", "--socket", "/run/agent.sock", "--auth-file", "relative.json"}, &stdout, &stderr); err == nil {
		t.Fatal("relative auth path was accepted")
	}
}
