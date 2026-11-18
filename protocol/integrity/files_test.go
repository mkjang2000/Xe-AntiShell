package integrity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

func TestReportRequiresExactTargetsAndBoundedTimestamps(t *testing.T) {
	now := time.Now().UTC()
	valid := func() Report {
		hash := strings.Repeat("a", 64)
		sample := Sample{State: "measured", SHA256: hash, MeasuredAt: now}
		rows := map[string]Sample{}
		for id := range Targets() {
			rows[id] = sample
		}
		return Report{Assignment: Assignment{EnrollmentID: "enrollment", Revision: 1, PolicySHA256: hash}, Package: managed.RPMPackage{Name: "xe-antishell", Version: "1", Release: "1.el9", Arch: "x86_64"}, RulePolicy: sample, CompletedAt: now, Samples: rows}
	}
	if !valid().Valid(now) {
		t.Fatal("valid report rejected")
	}
	for name, mutate := range map[string]func(*Report){
		"unknown target": func(r *Report) { delete(r.Samples, ConfigID); r.Samples["extra"] = r.RulePolicy },
		"invalid digest": func(r *Report) { r.PolicySHA256 = strings.Repeat("X", 64) },
		"partial sample": func(r *Report) {
			r.Samples[ConfigID] = Sample{State: "missing", SHA256: r.PolicySHA256, MeasuredAt: now}
		},
		"future finish":      func(r *Report) { r.CompletedAt = now.Add(time.Hour) },
		"out of range":       func(r *Report) { r.RulePolicy.MeasuredAt = time.Date(1400, 1, 1, 0, 0, 0, 0, time.UTC) },
		"future measurement": func(r *Report) { r.RulePolicy.MeasuredAt = now.Add(time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			r := valid()
			mutate(&r)
			if r.Valid(now) {
				t.Error("invalid report accepted")
			}
		})
	}
}

func TestPolicyDigestBindsSignedEnvelope(t *testing.T) {
	p := managed.SignedPolicy{KeyID: "operator-a", Signature: "first"}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	expected := sha256.Sum256(raw)
	sum, err := PolicyDigest(p)
	if err != nil || sum != hex.EncodeToString(expected[:]) {
		t.Fatal(sum, err)
	}
	p.Signature = "second"
	other, err := PolicyDigest(p)
	if err != nil || other == sum {
		t.Fatal("signature change not measured", err)
	}
}
