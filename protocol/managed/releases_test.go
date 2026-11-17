package managed

import (
	"crypto/ed25519"
	"testing"
)

func TestCentralAuthorizationCannotForgePublisherRelease(t *testing.T) {
	public, private, _ := GenerateSigningKey()
	central := map[string]ed25519.PublicKey{"central": public}
	plan := updateFixture()
	valid, err := SignUpdatePlan(plan, "central", private)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyUpdatePlan(valid, central, testPublisherKeys(), plan.AgentID, plan.EnrollmentID, plan.Revision, plan.IssuedAt); err != nil {
		t.Fatal(err)
	}
	// A compromised controller may authorize deployments but has no publisher key.
	plan.Release.Publisher, err = SignReleaseManifest(plan.Release.Publisher.Manifest, "test-release", private)
	if err != nil {
		t.Fatal(err)
	}
	forged, err := SignUpdatePlan(plan, "central", private)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyUpdatePlan(forged, central, testPublisherKeys(), plan.AgentID, plan.EnrollmentID, plan.Revision, plan.IssuedAt); err == nil {
		t.Fatal("central key accepted as release publisher")
	}
}

func TestReleasePublisherSignatureAndArtifactBinding(t *testing.T) {
	plan := updateFixture()
	signed := plan.Release.Publisher
	if _, err := VerifyReleaseManifest(signed, testPublisherKeys()); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*SignedReleaseManifest){
		func(s *SignedReleaseManifest) { s.Manifest.Size++ },
		func(s *SignedReleaseManifest) {
			s.Manifest.SHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab"
		},
		func(s *SignedReleaseManifest) { s.Manifest.Package.Release = "24.el9" },
		func(s *SignedReleaseManifest) { s.KeyID = "unknown" },
	} {
		copy := signed
		change(&copy)
		if _, err := VerifyReleaseManifest(copy, testPublisherKeys()); err == nil {
			t.Fatal("publisher tampering accepted")
		}
	}
	plan.Release.Publisher.Manifest.ArtifactName = "../../escape.rpm"
	if plan.Release.Validate() == nil {
		t.Fatal("unsafe publisher artifact name accepted")
	}
	plan = updateFixture()
	plan.Release.Size++
	if plan.Release.Validate() == nil {
		t.Fatal("publisher metadata detached from deployed artifact")
	}
}

func TestBuiltinPublisherAnchorsAreIndependentCopies(t *testing.T) {
	first := BuiltinReleasePublisherKeys()
	for id, key := range first {
		key[0] ^= 1
		if string(BuiltinReleasePublisherKeys()[id]) == string(key) {
			t.Fatal("mutable global publisher trust")
		}
	}
}

func TestRPMMetadataQueryIsBoundedAndIndependentOfFilename(t *testing.T) {
	pack, major, err := ParseRPMMetadata([]byte("xe-antishell\n0\n0.1.0\n24.el9_8\nx86_64\n"))
	if err != nil || major != "9" || pack.Release != "24.el9_8" {
		t.Fatal("valid package metadata rejected")
	}
	for _, body := range []string{"other\n0\n1.0\n1.el9\nx86_64\n", "xe-antishell\nnot-numeric\n1.0\n1.el9\nx86_64\n", "xe-antishell\n0\n1.0\n1.el10\nx86_64\nextra", "xe-antishell\n0\n1.0\n1\nx86_64\n"} {
		if _, _, err := ParseRPMMetadata([]byte(body)); err == nil {
			t.Fatal("untrusted package metadata accepted")
		}
	}
}
