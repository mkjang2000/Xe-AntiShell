package managedclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

func updateClient(t *testing.T, handler http.Handler) *Client {
	t.Helper()
	pki := createTestPKI(t)
	key, csr, err := GenerateCSR("agent")
	if err != nil {
		t.Fatal(err)
	}
	client, err := New("https://central.test", pki.caPEM, pki.issue(t, csr, "agent", "enrollment"), key)
	if err != nil {
		t.Fatal(err)
	}
	pipeTransport(client, pki, handler, nil)
	t.Cleanup(client.Close)
	return client
}

func TestUpdateArtifactUsesPinnedAuthenticatedBoundedStream(t *testing.T) {
	payload := bytes.Repeat([]byte("public-rpm-fixture"), 100000) // larger than JSON transport budget
	hash := sha256.Sum256(payload)
	release := managed.UpdateRelease{ID: "release", OSFamily: "rhel", OSMajor: "9", SHA256: hex.EncodeToString(hash[:]), Size: int64(len(payload)), CreatedAt: time.Now(), Package: managed.RPMPackage{Name: "xe-antishell", Version: "0.1.0", Release: "23.el9", Arch: "x86_64"}}
	_, publisher, _ := ed25519.GenerateKey(rand.Reader)
	release.Publisher, _ = managed.SignReleaseManifest(managed.ReleaseManifest{SchemaVersion: managed.SchemaVersion, ArtifactName: "xe-antishell-0.1.0-23.el9.x86_64.rpm", Package: release.Package, OSFamily: release.OSFamily, OSMajor: release.OSMajor, SHA256: release.SHA256, Size: release.Size, PublishedAt: release.CreatedAt}, "test-publisher", publisher)
	for _, scenario := range []string{"valid", "size", "hash", "redirect", "compression"} {
		t.Run(scenario, func(t *testing.T) {
			client := updateClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/update/artifacts/"+release.SHA256 || r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
					t.Error("artifact escaped pinned mTLS route")
				}
				switch scenario {
				case "size":
					_, _ = w.Write(payload[:len(payload)-1])
					return
				case "hash":
					_, _ = w.Write(bytes.Repeat([]byte("x"), len(payload)))
					return
				case "redirect":
					w.Header().Set("Location", "https://untrusted.invalid/package.rpm")
					w.WriteHeader(http.StatusFound)
					return
				case "compression":
					w.Header().Set("Content-Encoding", "gzip")
				}
				_, _ = w.Write(payload)
			}))
			var destination bytes.Buffer
			err := client.DownloadUpdateArtifact(context.Background(), release, &destination)
			if scenario == "valid" {
				if err != nil || !bytes.Equal(destination.Bytes(), payload) {
					t.Fatalf("valid stream failed: %v", err)
				}
			} else if err == nil {
				t.Fatal("invalid stream accepted")
			}
		})
	}
}

func TestUpdateCallsRequireIdentityAndUseSeparateRoutes(t *testing.T) {
	pki := createTestPKI(t)
	anonymous, err := New("https://central.test", pki.caPEM, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer anonymous.Close()
	if _, err := anonymous.DesiredUpdate(context.Background()); !errors.Is(err, ErrIdentityRequired) {
		t.Fatal("anonymous update poll accepted")
	}
	if err := anonymous.DownloadUpdateArtifact(context.Background(), managed.UpdateRelease{}, io.Discard); !errors.Is(err, ErrIdentityRequired) {
		t.Fatal("anonymous artifact accepted")
	}
	var calls atomic.Int64
	client := updateClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path == "/v1/heartbeat" {
			t.Error("updates changed heartbeat route")
		}
		if r.URL.Path == "/v1/update" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.URL.Path != "/v1/update/status" && r.URL.Path != "/v1/update/report" {
			t.Error("unexpected update route")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	if value, err := client.DesiredUpdate(context.Background()); err != nil || value != nil {
		t.Fatal("no-content update response failed")
	}
	if err := client.UpdateInventory(context.Background(), managed.UpdateInventory{ProtocolVersion: managed.UpdateProtocolVersion, RunningVersion: "unknown", ObservedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := client.ReportUpdate(context.Background(), managed.UpdateReport{ProtocolVersion: managed.UpdateProtocolVersion, JobID: "job", EnrollmentID: "enrollment", Revision: 1, Sequence: 1, State: "failed", ErrorCode: "interrupted", RunningVersion: "unknown", ObservedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 3 {
		t.Fatal("missing separate update requests")
	}
	if !UpdateUnsupported(&StatusError{Code: 404}) || UpdateUnsupported(errors.New(strings.Repeat("private", 3))) {
		t.Fatal("unsupported endpoint classification changed")
	}
}
