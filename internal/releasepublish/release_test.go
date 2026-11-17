package releasepublish

import (
	"bytes"
	"crypto/ed25519"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

func TestPrivateKeyGenerationIsExclusiveAndOnlyPublicDataIsPrinted(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "keys")
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"keygen", "--dir", directory}, &stdout, &stderr); code != 0 {
		t.Fatalf("keygen failed: %s", stderr.String())
	}
	path := filepath.Join(directory, "publisher-key.pem")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stdout.String(), "PRIVATE KEY") || strings.Contains(stdout.String(), string(before)) {
		t.Fatal("private key reached command output")
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Fatal("private key permissions are not private")
	}
	key, err := ReadPrivateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	if !strings.Contains(stdout.String(), Public(key).KeyID) {
		t.Fatal("public identity was not reported")
	}
	if _, err := GenerateKey(directory); err == nil {
		t.Fatal("existing private key overwritten")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("key generation replaced an existing key")
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPrivateKey(path); err == nil {
		t.Fatal("publicly readable private key accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "symlink.pem")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPrivateKey(link); err == nil {
		t.Fatal("symlinked key accepted")
	}
}

func TestManifestBindsBytesBeforeReleaseSigning(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "xe-antishell-test.rpm")
	if err := os.WriteFile(path, []byte("SYNTHETIC_ARTIFACT_NOT_AN_RPM"), 0o600); err != nil {
		t.Fatal(err)
	}
	hash, size, err := ArtifactFacts(path)
	if err != nil {
		t.Fatal(err)
	}
	m := managed.ReleaseManifest{SchemaVersion: managed.SchemaVersion, ArtifactName: filepath.Base(path), Package: managed.RPMPackage{Name: "xe-antishell", Version: "0.1.0", Release: "24.el9", Arch: "x86_64"}, OSFamily: "rhel", OSMajor: "9", SHA256: hash, Size: size, PublishedAt: time.Now().UTC()}
	if err := CheckArtifact(m, path); err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := managed.GenerateSigningKey()
	defer clear(priv)
	signed, err := managed.SignReleaseManifest(m, "test-publisher", priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := managed.VerifyReleaseManifest(signed, map[string]ed25519.PublicKey{"test-publisher": pub}); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(directory, "manifest.json")
	if err := WriteJSON(manifest, signed, 0o644); err != nil {
		t.Fatal(err)
	}
	var read managed.SignedReleaseManifest
	if err := ReadJSON(manifest, &read); err != nil {
		t.Fatal(err)
	}
	if read.Signature != signed.Signature {
		t.Fatal("signature changed on disk")
	}
	if err := WriteJSON(manifest, signed, 0o644); err == nil {
		t.Fatal("immutable release output replaced")
	}
	if err := os.WriteFile(path, []byte("TAMPERED"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckArtifact(m, path); err == nil {
		t.Fatal("tampered release artifact accepted")
	}
}

func TestCommandErrorsDoNotEchoPrivateInput(t *testing.T) {
	directory := t.TempDir()
	private := filepath.Join(directory, "invalid.pem")
	if err := os.WriteFile(private, []byte("PRIVATE_TEST_DATA_MUST_NOT_PRINT"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if Run([]string{"public", "--key", private}, &stdout, &stderr) == 0 {
		t.Fatal("invalid private key accepted")
	}
	if strings.Contains(stdout.String()+stderr.String(), "PRIVATE_TEST_DATA_MUST_NOT_PRINT") {
		t.Fatal("private input leaked into diagnostics")
	}
}

func TestRPMQueryWriterCannotBypassBoundWithReaderFrom(t *testing.T) {
	var output queryOutput
	_, err := io.Copy(&output, strings.NewReader(strings.Repeat("x", 8192)))
	if err == nil || len(output.buffer) > 4096 {
		t.Fatal("RPM query output exceeded bound")
	}
}
