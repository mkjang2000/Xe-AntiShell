package managed

import (
	"crypto/ed25519"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const MaxReleaseManifestBytes = 16 << 10

// ParseRPMMetadata handles only fixed NAME/EPOCHNUM/VERSION/RELEASE/ARCH query
// output. It never extracts or executes an RPM payload or scriptlet.
func ParseRPMMetadata(data []byte) (RPMPackage, string, error) {
	if len(data) > 4096 {
		return RPMPackage{}, "", errors.New("RPM metadata exceeds limit")
	}
	fields := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(fields) != 5 {
		return RPMPackage{}, "", errors.New("invalid RPM metadata fields")
	}
	epoch, err := strconv.ParseUint(fields[1], 10, 32)
	p := RPMPackage{Name: fields[0], Epoch: epoch, Version: fields[2], Release: fields[3], Arch: fields[4]}
	match := elRelease.FindStringSubmatch(p.Release)
	if err != nil || p.Validate() != nil || len(match) != 2 {
		return RPMPackage{}, "", errors.New("unsupported agent RPM metadata")
	}
	return p, match[1], nil
}

// ReleaseManifest is signed by the build publisher, independently of central's
// per-enrollment deployment authorization. It contains no installation commands.
type ReleaseManifest struct {
	SchemaVersion string     `json:"schema_version"`
	ArtifactName  string     `json:"artifact_name"`
	Package       RPMPackage `json:"package"`
	OSFamily      string     `json:"os_family"`
	OSMajor       string     `json:"os_major"`
	SHA256        string     `json:"sha256"`
	Size          int64      `json:"size"`
	PublishedAt   time.Time  `json:"published_at"`
}

type SignedReleaseManifest struct {
	Manifest  ReleaseManifest `json:"manifest"`
	KeyID     string          `json:"key_id"`
	Signature string          `json:"signature"`
}

var releaseArtifactName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+~^-]{0,220}\.rpm$`)

func (m ReleaseManifest) Validate() error {
	if m.SchemaVersion != SchemaVersion || !releaseArtifactName.MatchString(m.ArtifactName) || m.Package.Validate() != nil || m.OSFamily != "rhel" || !validUpdateMajor(m.OSMajor) || !updateHash.MatchString(m.SHA256) || m.Size < 1 || m.Size > MaxUpdateArtifactBytes || m.PublishedAt.IsZero() {
		return errors.New("invalid publisher release manifest")
	}
	match := elRelease.FindStringSubmatch(m.Package.Release)
	if len(match) != 2 || match[1] != m.OSMajor {
		return errors.New("publisher package platform mismatch")
	}
	return nil
}

func (s SignedReleaseManifest) Matches(release UpdateRelease) bool {
	m := s.Manifest
	return m.Validate() == nil && validIdentifier(s.KeyID, 128) && len(s.Signature) > 0 && len(s.Signature) <= 1024 &&
		m.Package == release.Package && m.OSFamily == release.OSFamily && m.OSMajor == release.OSMajor && m.SHA256 == release.SHA256 && m.Size == release.Size
}

func SignReleaseManifest(manifest ReleaseManifest, keyID string, private ed25519.PrivateKey) (SignedReleaseManifest, error) {
	if err := manifest.Validate(); err != nil {
		return SignedReleaseManifest{}, err
	}
	signature, err := signValue("release-manifest", keyID, manifest, private, MaxReleaseManifestBytes)
	return SignedReleaseManifest{Manifest: manifest, KeyID: keyID, Signature: signature}, err
}

func VerifyReleaseManifest(signed SignedReleaseManifest, trusted map[string]ed25519.PublicKey) (ReleaseManifest, error) {
	if err := signed.Manifest.Validate(); err != nil {
		return ReleaseManifest{}, err
	}
	if err := verifyValue("release-manifest", signed.KeyID, signed.Manifest, signed.Signature, trusted, MaxReleaseManifestBytes); err != nil {
		return ReleaseManifest{}, err
	}
	return signed.Manifest, nil
}

// These are public trust anchors built into central and the agent. Changing a
// runtime policy or an uploaded manifest cannot add a release publisher key.
// The signing private key is never part of this module or any RPM payload.
func BuiltinReleasePublisherKeys() map[string]ed25519.PublicKey {
	key, err := DecodePublicKey("kCQIqa0FuaNctE6p5NZtvSv4b9T44/RC7x4Ay/pOz2M=")
	if err != nil {
		panic("invalid embedded release public key")
	}
	return map[string]ed25519.PublicKey{"release-791c4b607e9cf708": key}
}
