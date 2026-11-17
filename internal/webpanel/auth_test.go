package webpanel

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testParameters() Argon2Parameters {
	return Argon2Parameters{Time: 1, Memory: 8 * 1024, Threads: 1, KeyLen: 32}
}

func testCredentials(t *testing.T) Credentials {
	t.Helper()
	credentials, err := GenerateCredentials("admin", "correct-horse-battery-staple", testParameters())
	if err != nil {
		t.Fatal(err)
	}
	return credentials
}

func TestCredentialsVerify(t *testing.T) {
	credentials := testCredentials(t)
	if !credentials.Verify("admin", "correct-horse-battery-staple") {
		t.Fatal("valid credentials were rejected")
	}
	if credentials.Verify("admin", "wrong-password-value") {
		t.Fatal("wrong password was accepted")
	}
	if credentials.Verify("other", "correct-horse-battery-staple") {
		t.Fatal("wrong username was accepted")
	}
}

func TestSessionRejectsTamperingAndExpiry(t *testing.T) {
	credentials := testCredentials(t)
	now := time.Unix(1_700_000_000, 0)
	token, err := credentials.NewSession(now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if username, err := credentials.VerifySession(token, now.Add(30*time.Minute)); err != nil || username != "admin" {
		t.Fatalf("verify valid session: username=%q err=%v", username, err)
	}
	tampered := token[:len(token)-1] + "x"
	if _, err := credentials.VerifySession(tampered, now); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("tampered session error = %v", err)
	}
	if _, err := credentials.VerifySession(token, now.Add(time.Hour)); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("expired session error = %v", err)
	}
}

func TestLoadCredentialsRejectsBroadPermissions(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "auth.json")
	credentials := testCredentials(t)
	if err := WriteCredentials(path, credentials); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadCredentials(path)
	if err != nil || loaded.Username != "admin" {
		t.Fatalf("load credentials: username=%q err=%v", loaded.Username, err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCredentials(path); err == nil {
		t.Fatal("broad auth file permissions were accepted")
	}
}

func TestWriteCredentialsRefusesOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.json")
	credentials := testCredentials(t)
	if err := WriteCredentials(path, credentials); err != nil {
		t.Fatal(err)
	}
	if err := WriteCredentials(path, credentials); err == nil {
		t.Fatal("credential overwrite was accepted")
	}
}
