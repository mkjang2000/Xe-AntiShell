package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

type enrollmentManagerFunc func(context.Context, string, any, any) error

func (f enrollmentManagerFunc) Management(ctx context.Context, action string, input, output any) error {
	return f(ctx, action, input, output)
}

func enrollmentCodeFixture(t *testing.T) (managed.InstallationCode, string) {
	t.Helper()
	now := time.Now()
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, private.Public(), private)
	if err != nil {
		t.Fatal(err)
	}
	code := managed.InstallationCode{
		Version: "1", CentralURL: "https://central.example:9443", AgentID: "install-test",
		Token: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		CAPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), ExpiresAt: now.Add(time.Hour),
	}
	encoded, err := managed.EncodeInstallationCode(code)
	if err != nil {
		t.Fatal(err)
	}
	return code, encoded
}

func TestEnrollCodePersistsRecoveryBeforeRequestAndReusesItOnRetry(t *testing.T) {
	code, encoded := enrollmentCodeFixture(t)
	directory := t.TempDir()
	codeFile, recoveryFile := filepath.Join(directory, "installation"), filepath.Join(directory, "recovery")
	if err := os.WriteFile(codeFile, []byte(encoded+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var firstRecovery string
	calls := 0
	client := enrollmentManagerFunc(func(_ context.Context, action string, input, output any) error {
		calls++
		data, ok := input.(map[string]string)
		if !ok || action != "enroll" || output != nil || data["url"] != code.CentralURL || data["agent_id"] != code.AgentID || data["ca_pem"] != code.CAPEM || data["token"] != code.Token {
			t.Fatal("installation fields did not reach the existing enrollment action")
		}
		body, err := readBoundedFile(recoveryFile, 128, true)
		if err != nil || strings.TrimSpace(string(body)) != data["recovery_code"] {
			t.Fatal("request preceded durable recovery preparation")
		}
		if calls == 1 {
			firstRecovery = data["recovery_code"]
			return errors.New("untrusted error: " + code.Token + " " + encoded + " " + firstRecovery)
		}
		if data["recovery_code"] != firstRecovery {
			t.Fatal("retry replaced the recovery credential")
		}
		return nil
	})
	var stdout, stderr bytes.Buffer
	args := []string{"--code-file", codeFile, "--recovery-file", recoveryFile}
	if err := runEnrollCode(context.Background(), client, args, &stdout, &stderr); err == nil || strings.Contains(err.Error(), code.Token) || strings.Contains(err.Error(), encoded) || strings.Contains(err.Error(), firstRecovery) {
		t.Fatal("enrollment failure was missing or disclosed credentials")
	}
	if err := runEnrollCode(context.Background(), client, args, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if calls != 2 || !strings.Contains(stdout.String(), code.AgentID) || !strings.Contains(stdout.String(), recoveryFile) {
		t.Fatal("successful retry did not report the identity and recovery file")
	}
	for _, secret := range []string{encoded, code.Token, firstRecovery, code.CAPEM} {
		if strings.Contains(stdout.String()+stderr.String(), secret) {
			t.Fatal("command output disclosed credentials")
		}
	}
}

func TestEnrollCodeRejectsInvalidInputBeforeRecoveryOrRequest(t *testing.T) {
	code, encoded := enrollmentCodeFixture(t)
	expired := code
	expired.ExpiresAt = time.Now().Add(-time.Minute)
	expiredCode, err := managed.EncodeInstallationCode(expired)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, body string
		mode       os.FileMode
	}{
		{"malformed", "xeas1.private-invalid-value", 0600},
		{"expired", expiredCode, 0600},
		{"oversized", strings.Repeat("x", managed.MaxInstallationCodeBytes+1), 0600},
		{"public", encoded, 0644},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			codeFile, recoveryFile := filepath.Join(directory, "installation"), filepath.Join(directory, "recovery")
			if err := os.WriteFile(codeFile, []byte(test.body), test.mode); err != nil {
				t.Fatal(err)
			}
			called := false
			client := enrollmentManagerFunc(func(context.Context, string, any, any) error { called = true; return nil })
			var stdout, stderr bytes.Buffer
			err := runEnrollCode(context.Background(), client, []string{"--code-file", codeFile, "--recovery-file", recoveryFile}, &stdout, &stderr)
			if err == nil || called || strings.Contains(err.Error(), test.body) {
				t.Fatal("invalid protected input reached enrollment or was disclosed")
			}
			if _, err := os.Stat(recoveryFile); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("invalid input created a recovery credential")
			}
		})
	}
}

func TestEnrollCodeRejectsSymlinkAndInvalidRecovery(t *testing.T) {
	_, encoded := enrollmentCodeFixture(t)
	directory := t.TempDir()
	codeFile, link, recoveryFile := filepath.Join(directory, "installation"), filepath.Join(directory, "link"), filepath.Join(directory, "recovery")
	if err := os.WriteFile(codeFile, []byte(encoded), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(codeFile, link); err != nil {
		t.Fatal(err)
	}
	client := enrollmentManagerFunc(func(context.Context, string, any, any) error { t.Fatal("invalid file reached enrollment"); return nil })
	var stdout, stderr bytes.Buffer
	if err := runEnrollCode(context.Background(), client, []string{"--code-file", link, "--recovery-file", recoveryFile}, &stdout, &stderr); err == nil {
		t.Fatal("symlink accepted")
	}
	if err := os.WriteFile(recoveryFile, []byte("invalid-existing-recovery"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := runEnrollCode(context.Background(), client, []string{"--code-file", codeFile, "--recovery-file", recoveryFile}, &stdout, &stderr); err == nil {
		t.Fatal("invalid recovery accepted")
	}
	body, err := os.ReadFile(recoveryFile)
	if err != nil || string(body) != "invalid-existing-recovery" {
		t.Fatal("existing recovery was replaced")
	}
}

func TestEnrollCodeFlagContractAndRootGate(t *testing.T) {
	if defaultRecoveryFile != "/root/xe-antishell-offline-recovery" {
		t.Fatal("unexpected default recovery location")
	}
	client := enrollmentManagerFunc(func(context.Context, string, any, any) error { t.Fatal("invalid flags reached enrollment"); return nil })
	var stdout, stderr bytes.Buffer
	for _, args := range [][]string{nil, {"--code-file"}, {"--code-file", "file", "extra"}, {"--code-file", "file", "--recovery-file", ""}, {"--token", "secret"}, {"--xeas1.private-code"}} {
		if err := runEnrollCode(context.Background(), client, args, &stdout, &stderr); err == nil {
			t.Fatal("invalid enrollment flags accepted")
		}
	}
	if strings.Contains(stdout.String()+stderr.String(), "private-code") {
		t.Fatal("flag diagnostics disclosed a mistakenly pasted installation code")
	}
	if os.Geteuid() != 0 {
		if err := runManaged(context.Background(), nil, []string{"enroll-code", "--code-file", "unused"}, &stdout, &stderr); err == nil || err.Error() != "managed changes require root" {
			t.Fatal("enroll-code bypassed the existing root requirement")
		}
	}
}
