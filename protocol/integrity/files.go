// Package integrity defines the optional file measurement exchange. It is
// independent of the signed policy and the v1 heartbeat wire formats.
package integrity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

const (
	MaxMessage = 8 << 10
	FreshFor   = 2 * time.Hour
	ConfigID   = "site-config"
)

// Targets returns a fresh allowlist. Remote policies may never add paths.
func Targets() map[string]string {
	return map[string]string{
		"sentineld":             "/usr/sbin/sentineld",
		"sentinel":              "/usr/bin/sentinel",
		"sentinel-web":          "/usr/sbin/sentinel-web",
		"sentinel-updater":      "/usr/sbin/sentinel-updater",
		"sentineld-unit":        "/usr/lib/systemd/system/sentineld.service",
		"sentinel-web-unit":     "/usr/lib/systemd/system/sentinel-web.service",
		"sentinel-updater-unit": "/usr/lib/systemd/system/sentinel-updater.service",
		ConfigID:                "/etc/xe-antishell/sentineld.yaml",
	}
}

type Assignment struct {
	EnrollmentID string `json:"enrollment_id"`
	Revision     uint64 `json:"revision"`
	PolicySHA256 string `json:"policy_sha256"`
}

type Sample struct {
	SHA256     string    `json:"sha256,omitempty"`
	State      string    `json:"state"`
	MeasuredAt time.Time `json:"measured_at"`
}

type Report struct {
	Assignment
	RulePolicy  Sample             `json:"rule_policy"`
	Package     managed.RPMPackage `json:"package"`
	Samples     map[string]Sample  `json:"samples"`
	CompletedAt time.Time          `json:"completed_at"`
}

func ValidDigest(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == sha256.Size && strings.ToLower(s) == s
}

func PolicyDigest(p managed.SignedPolicy) (string, error) {
	raw, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:]), nil
}

// Measurement times are persisted as signed Unix nanoseconds.
func validTime(t time.Time) bool {
	return !t.IsZero() && time.Unix(0, t.UnixNano()).Equal(t)
}

func (r Report) Valid(now time.Time) bool {
	if r.EnrollmentID == "" || len(r.EnrollmentID) > 160 || r.Revision == 0 || !ValidDigest(r.PolicySHA256) || r.Package.Validate() != nil || !validTime(r.CompletedAt) || r.CompletedAt.After(now.Add(time.Minute)) || len(r.Samples) != len(Targets()) {
		return false
	}
	targets := Targets()
	targets["signed-policy"] = ""
	for id := range targets {
		s, ok := r.Samples[id]
		if id == "signed-policy" {
			s, ok = r.RulePolicy, true
		}
		if !ok || !validTime(s.MeasuredAt) || s.MeasuredAt.After(r.CompletedAt) {
			return false
		}
		switch s.State {
		case "measured":
			if !ValidDigest(s.SHA256) {
				return false
			}
		case "missing", "unreadable", "changed_during_read", "too_large":
			if s.SHA256 != "" {
				return false
			}
		default:
			return false
		}
	}
	return true
}
