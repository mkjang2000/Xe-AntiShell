package updates

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeRunner struct {
	installed, candidate    managed.RPMPackage
	commands                []string
	installCount            int
	testError, installError error
	beforeTest              func()
	beforeInstall           func()
	beforeQuery             func()
}

func (r *fakeRunner) Run(_ context.Context, command string, args ...string) ([]byte, error) {
	call := command + " " + strings.Join(args, " ")
	r.commands = append(r.commands, call)
	if command == "/usr/bin/rpm" {
		if args[0] == "-q" || args[0] == "-qp" {
			if r.beforeQuery != nil {
				r.beforeQuery()
			}
			p := r.installed
			if args[0] == "-qp" {
				p = r.candidate
			}
			return []byte(fmt.Sprintf("%s\n%d\n%s\n%s\n%s\n", p.Name, p.Epoch, p.Version, p.Release, p.Arch)), nil
		}
		if len(args) > 1 && args[1] == "--test" {
			if r.beforeTest != nil {
				r.beforeTest()
			}
			return nil, r.testError
		}
		if r.beforeInstall != nil {
			r.beforeInstall()
		}
		r.installCount++
		if r.installError == nil {
			r.installed = r.candidate
		}
		return nil, r.installError
	}
	return nil, nil
}

type fakeClient struct {
	plan             *managed.SignedUpdatePlan
	private          ed25519.PrivateKey
	publisherPrivate ed25519.PrivateKey
	now              func() time.Time
	artifact         []byte
	claims           int
	reports          []managed.UpdateReport
	loseReply        bool
	claimError       error
}

func (c *fakeClient) DesiredUpdate(context.Context) (*managed.SignedUpdatePlan, error) {
	return c.plan, nil
}
func (c *fakeClient) DownloadUpdateArtifact(_ context.Context, _ managed.UpdateRelease, output io.Writer) error {
	_, err := output.Write(c.artifact)
	return err
}
func (c *fakeClient) ClaimUpdate(_ context.Context, claim managed.UpdateClaim) (managed.SignedUpdateAuthorization, error) {
	c.claims++
	if c.claimError != nil {
		return managed.SignedUpdateAuthorization{}, c.claimError
	}
	digest, _ := managed.UpdatePlanDigest(c.plan.Plan)
	return managed.SignUpdateAuthorization(managed.UpdateAuthorization{ProtocolVersion: managed.UpdateProtocolVersion, JobID: claim.JobID, AgentID: c.plan.Plan.AgentID, EnrollmentID: claim.EnrollmentID, Revision: claim.Revision, PlanSHA256: digest, IssuedAt: c.now(), ExpiresAt: c.now().Add(2 * time.Minute)}, "key", c.private)
}
func (c *fakeClient) ReportUpdate(_ context.Context, report managed.UpdateReport) error {
	c.reports = append(c.reports, report)
	if c.loseReply {
		c.loseReply = false
		return errors.New("lost reply")
	}
	return nil
}

func fixture(t *testing.T) (*Manager, *fakeClient, Identity, managed.UpdateInventory, *fakeRunner, *time.Time) {
	t.Helper()
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	publisherPublic, publisherPrivate, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	current := managed.RPMPackage{Name: "xe-antishell", Version: "0.1.0", Release: "23.el9", Arch: "x86_64"}
	target := current
	target.Release = "24.el9"
	artifact := []byte("PUBLIC_SYNTHETIC_RPM_NOT_EXECUTABLE")
	hash := sha256.Sum256(artifact)
	plan := managed.UpdatePlan{ProtocolVersion: managed.UpdateProtocolVersion, JobID: "job-a", RolloutID: "rollout-a", AgentID: "agent-a", EnrollmentID: "enrollment-a", Revision: 1, IssuedAt: now, ExpiresAt: now.Add(15 * time.Minute), ExpectedPackage: current,
		Release: managed.UpdateRelease{ID: "release-a", Package: target, OSFamily: "rhel", OSMajor: "9", SHA256: hex.EncodeToString(hash[:]), Size: int64(len(artifact)), CreatedAt: now}}
	plan.Release.Publisher, _ = managed.SignReleaseManifest(managed.ReleaseManifest{SchemaVersion: managed.SchemaVersion, ArtifactName: "xe-antishell-0.1.0-24.el9.x86_64.rpm", Package: target, OSFamily: "rhel", OSMajor: "9", SHA256: plan.Release.SHA256, Size: plan.Release.Size, PublishedAt: now}, "publisher", publisherPrivate)
	signed, err := managed.SignUpdatePlan(plan, "key", private)
	if err != nil {
		t.Fatal(err)
	}
	identity := Identity{plan.AgentID, plan.EnrollmentID, "key", managed.EncodePublicKey(public)}
	runner := &fakeRunner{installed: current, candidate: target}
	manager := &Manager{Store: &Store{Directory: filepath.Join(t.TempDir(), "updates"), OwnerUID: uint32(os.Geteuid())}, Runner: runner, Now: func() time.Time { return now },
		PublisherKeys:  map[string]ed25519.PublicKey{"publisher": publisherPublic},
		RunningVersion: func(context.Context) string { return PackageVersion(current) },
		Healthy:        func(context.Context, managed.UpdatePlan) bool { return true }, CheckLocal: func(context.Context, managed.UpdatePlan) error { return nil },
		CurrentIdentity: func(context.Context) (Identity, error) { return identity, nil }, Platform: func() (string, string, string) { return "rhel", "9", "x86_64" }, HealthTimeout: time.Millisecond}
	client := &fakeClient{plan: &signed, private: private, publisherPrivate: publisherPrivate, artifact: artifact, now: manager.Now}
	inventory := managed.UpdateInventory{ProtocolVersion: managed.UpdateProtocolVersion, Supported: true, Enabled: true, OSFamily: "rhel", OSMajor: "9", Arch: "x86_64", RunningVersion: PackageVersion(current), InstalledPackage: &current, ObservedAt: now}
	return manager, client, identity, inventory, runner, &now
}
