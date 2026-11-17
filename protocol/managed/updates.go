package managed

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"regexp"
	"time"
)

const (
	UpdateProtocolVersion        = 1
	MaxUpdateBytes               = 32 << 10
	MaxUpdateArtifactBytes int64 = 64 << 20
)

type RPMPackage struct {
	Name    string `json:"name"`
	Epoch   uint64 `json:"epoch"`
	Version string `json:"version"`
	Release string `json:"release"`
	Arch    string `json:"arch"`
}

type UpdateRelease struct {
	ID        string     `json:"id"`
	Package   RPMPackage `json:"package"`
	OSFamily  string     `json:"os_family"`
	OSMajor   string     `json:"os_major"`
	SHA256    string     `json:"sha256"`
	Size      int64      `json:"size"`
	CreatedAt time.Time  `json:"created_at"`
}

type UpdatePlan struct {
	ProtocolVersion int           `json:"protocol_version"`
	JobID           string        `json:"job_id"`
	RolloutID       string        `json:"rollout_id"`
	AgentID         string        `json:"agent_id"`
	EnrollmentID    string        `json:"enrollment_id"`
	Revision        uint64        `json:"revision"`
	IssuedAt        time.Time     `json:"issued_at"`
	ExpiresAt       time.Time     `json:"expires_at"`
	Release         UpdateRelease `json:"release"`
	ExpectedPackage RPMPackage    `json:"expected_package"`
}

type SignedUpdatePlan struct {
	Plan      UpdatePlan `json:"plan"`
	KeyID     string     `json:"key_id"`
	Signature string     `json:"signature"`
}

// A short lease is issued only after download, against the still-current job.
type UpdateAuthorization struct {
	ProtocolVersion int       `json:"protocol_version"`
	JobID           string    `json:"job_id"`
	AgentID         string    `json:"agent_id"`
	EnrollmentID    string    `json:"enrollment_id"`
	Revision        uint64    `json:"revision"`
	PlanSHA256      string    `json:"plan_sha256"`
	IssuedAt        time.Time `json:"issued_at"`
	ExpiresAt       time.Time `json:"expires_at"`
}

type SignedUpdateAuthorization struct {
	Authorization UpdateAuthorization `json:"authorization"`
	KeyID         string              `json:"key_id"`
	Signature     string              `json:"signature"`
}

// Inventory travels separately so old strict heartbeat decoders remain compatible.
type UpdateInventory struct {
	ProtocolVersion  int         `json:"protocol_version"`
	Supported        bool        `json:"supported"`
	Enabled          bool        `json:"enabled"`
	ReasonCode       string      `json:"reason_code,omitempty"`
	OSFamily         string      `json:"os_family,omitempty"`
	OSMajor          string      `json:"os_major,omitempty"`
	Arch             string      `json:"arch,omitempty"`
	InstalledPackage *RPMPackage `json:"installed_package,omitempty"`
	RunningVersion   string      `json:"running_version"`
	ObservedAt       time.Time   `json:"observed_at"`
}

type UpdateClaim struct {
	JobID        string `json:"job_id"`
	EnrollmentID string `json:"enrollment_id"`
	Revision     uint64 `json:"revision"`
}

type UpdateReport struct {
	ProtocolVersion  int         `json:"protocol_version"`
	JobID            string      `json:"job_id"`
	EnrollmentID     string      `json:"enrollment_id"`
	Revision         uint64      `json:"revision"`
	Sequence         uint64      `json:"sequence"`
	State            string      `json:"state"`
	ErrorCode        string      `json:"error_code,omitempty"`
	InstalledPackage *RPMPackage `json:"installed_package,omitempty"`
	RunningVersion   string      `json:"running_version"`
	ObservedAt       time.Time   `json:"observed_at"`
}

var rpmComponent = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+~^%-]{0,127}$`)
var updateHash = regexp.MustCompile(`^[0-9a-f]{64}$`)
var elRelease = regexp.MustCompile(`(?:^|\.)el(7|8|9|10)(?:\.|$)`)

func (p RPMPackage) Validate() error {
	if p.Name != "xe-antishell" || p.Epoch > math.MaxUint32 || !rpmComponent.MatchString(p.Version) || !rpmComponent.MatchString(p.Release) || p.Arch != "x86_64" {
		return errors.New("unsupported agent RPM metadata")
	}
	return nil
}

func (r UpdateRelease) Validate() error {
	if !validIdentifier(r.ID, 128) || r.Package.Validate() != nil || r.OSFamily != "rhel" || !validUpdateMajor(r.OSMajor) || !updateHash.MatchString(r.SHA256) || r.Size < 1 || r.Size > MaxUpdateArtifactBytes || r.CreatedAt.IsZero() {
		return errors.New("invalid update release")
	}
	match := elRelease.FindStringSubmatch(r.Package.Release)
	if len(match) != 2 || match[1] != r.OSMajor {
		return errors.New("RPM release does not match target EL major")
	}
	return nil
}

func (p UpdatePlan) Validate() error {
	if p.ProtocolVersion != UpdateProtocolVersion || !validIdentifier(p.JobID, 128) || !validIdentifier(p.RolloutID, 128) || !validUpdateTarget(p.AgentID, p.EnrollmentID, p.Revision) || !updateInterval(p.IssuedAt, p.ExpiresAt, 24*time.Hour) || p.Release.Validate() != nil || p.ExpectedPackage.Validate() != nil {
		return errors.New("invalid update plan")
	}
	return nil
}

func (a UpdateAuthorization) Validate() error {
	if a.ProtocolVersion != UpdateProtocolVersion || !validIdentifier(a.JobID, 128) || !validUpdateTarget(a.AgentID, a.EnrollmentID, a.Revision) || !updateHash.MatchString(a.PlanSHA256) || !updateInterval(a.IssuedAt, a.ExpiresAt, 5*time.Minute) {
		return errors.New("invalid update authorization")
	}
	return nil
}

func (i UpdateInventory) Validate() error {
	if i.ProtocolVersion != UpdateProtocolVersion || !ValidUpdateCode(i.ReasonCode) || !validBuildVersion(i.RunningVersion) || i.ObservedAt.IsZero() || len(i.OSFamily) > 32 || len(i.OSMajor) > 16 || len(i.Arch) > 32 {
		return errors.New("invalid update inventory")
	}
	if i.InstalledPackage != nil && i.InstalledPackage.Validate() != nil {
		return errors.New("invalid installed package")
	}
	if i.Supported && (i.InstalledPackage == nil || i.OSFamily != "rhel" || !validUpdateMajor(i.OSMajor) || i.Arch != "x86_64") {
		return errors.New("incomplete supported update inventory")
	}
	return nil
}

func (c UpdateClaim) Validate() error {
	if !validIdentifier(c.JobID, 128) || !validIdentifier(c.EnrollmentID, 160) || c.Revision < 1 || c.Revision > math.MaxInt64 {
		return errors.New("invalid update claim")
	}
	return nil
}

func (r UpdateReport) Validate() error {
	if r.ProtocolVersion != UpdateProtocolVersion || !validIdentifier(r.JobID, 128) || !validIdentifier(r.EnrollmentID, 160) || r.Revision < 1 || r.Revision > math.MaxInt64 || r.Sequence < 1 || r.Sequence > math.MaxInt64 || !ValidUpdateCode(r.ErrorCode) || !validBuildVersion(r.RunningVersion) || r.ObservedAt.IsZero() {
		return errors.New("invalid update report")
	}
	switch r.State {
	case "downloading", "ready", "installing", "succeeded", "failed":
	default:
		return errors.New("invalid agent update state")
	}
	if r.State == "failed" && (r.ErrorCode == "" || r.ErrorCode == "none") {
		return errors.New("failed update requires fixed error code")
	}
	if r.State != "failed" && r.ErrorCode != "" && r.ErrorCode != "none" {
		return errors.New("unexpected update error code")
	}
	if r.InstalledPackage != nil && r.InstalledPackage.Validate() != nil {
		return errors.New("invalid installed package")
	}
	if r.State == "succeeded" && r.InstalledPackage == nil {
		return errors.New("successful update requires installed package")
	}
	return nil
}

func SignUpdatePlan(plan UpdatePlan, keyID string, private ed25519.PrivateKey) (SignedUpdatePlan, error) {
	if err := plan.Validate(); err != nil {
		return SignedUpdatePlan{}, err
	}
	sig, err := signValue("update-plan", keyID, plan, private, MaxUpdateBytes)
	return SignedUpdatePlan{Plan: plan, KeyID: keyID, Signature: sig}, err
}

func VerifyUpdatePlan(signed SignedUpdatePlan, trusted map[string]ed25519.PublicKey, agentID, enrollmentID string, minimumRevision uint64, now time.Time) (UpdatePlan, error) {
	if err := verifyValue("update-plan", signed.KeyID, signed.Plan, signed.Signature, trusted, MaxUpdateBytes); err != nil {
		return UpdatePlan{}, err
	}
	p := signed.Plan
	if p.Validate() != nil || p.AgentID != agentID || p.EnrollmentID != enrollmentID || p.Revision < minimumRevision || !updateCurrent(p.IssuedAt, p.ExpiresAt, now) {
		return UpdatePlan{}, errors.New("update plan target, revision or validity rejected")
	}
	return p, nil
}

func UpdatePlanDigest(plan UpdatePlan) (string, error) {
	if err := plan.Validate(); err != nil {
		return "", err
	}
	body, err := json.Marshal(plan)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:]), nil
}

func SignUpdateAuthorization(a UpdateAuthorization, keyID string, private ed25519.PrivateKey) (SignedUpdateAuthorization, error) {
	if err := a.Validate(); err != nil {
		return SignedUpdateAuthorization{}, err
	}
	sig, err := signValue("update-install", keyID, a, private, MaxUpdateBytes)
	return SignedUpdateAuthorization{Authorization: a, KeyID: keyID, Signature: sig}, err
}

func VerifyUpdateAuthorization(signed SignedUpdateAuthorization, trusted map[string]ed25519.PublicKey, plan UpdatePlan, now time.Time) (UpdateAuthorization, error) {
	if err := verifyValue("update-install", signed.KeyID, signed.Authorization, signed.Signature, trusted, MaxUpdateBytes); err != nil {
		return UpdateAuthorization{}, err
	}
	a := signed.Authorization
	digest, err := UpdatePlanDigest(plan)
	if err != nil || a.Validate() != nil || a.JobID != plan.JobID || a.AgentID != plan.AgentID || a.EnrollmentID != plan.EnrollmentID || a.Revision != plan.Revision || a.PlanSHA256 != digest || a.ExpiresAt.After(plan.ExpiresAt) || !updateCurrent(a.IssuedAt, a.ExpiresAt, now) || !updateCurrent(plan.IssuedAt, plan.ExpiresAt, now) {
		return UpdateAuthorization{}, errors.New("update install authorization rejected")
	}
	return a, nil
}

// Codes are fixed diagnostics; raw command stderr and network bodies are forbidden.
func ValidUpdateCode(code string) bool {
	switch code {
	case "", "none", "disabled", "not_enrolled", "central_unsupported", "unsupported_platform", "unsupported_os", "unsupported_arch", "unsupported_package", "rpm_unavailable", "systemd_unavailable", "helper_unavailable", "custom_paths", "identity_unavailable", "state_unavailable", "signature_invalid", "expired", "target_mismatch", "stale_job", "precondition_changed", "download_failed", "size_mismatch", "hash_mismatch", "metadata_mismatch", "rpm_test_failed", "install_failed", "restart_failed", "health_check_failed", "verification_failed", "interrupted", "busy", "service_unavailable", "queue_failed":
		return true
	}
	return false
}

func validUpdateMajor(major string) bool {
	return major == "7" || major == "8" || major == "9" || major == "10"
}
func validUpdateTarget(agent, enrollment string, revision uint64) bool {
	return validIdentifier(agent, 128) && validIdentifier(enrollment, 160) && revision >= 1 && revision <= math.MaxInt64
}
func updateInterval(issued, expires time.Time, maximum time.Duration) bool {
	return !issued.IsZero() && !expires.IsZero() && expires.After(issued) && expires.Sub(issued) <= maximum
}
func updateCurrent(issued, expires, now time.Time) bool {
	return !issued.After(now.Add(time.Minute)) && now.Before(expires)
}
func validBuildVersion(value string) bool { return validName(value, true) && len(value) <= 128 }
