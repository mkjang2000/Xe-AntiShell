// Package identity creates local identifiers without relying on collector- or
// database-specific sequences.
package identity

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	"xe-antishell/internal/model"
)

// NewID returns a random 128-bit identifier prefixed with a stable object kind.
func NewID(prefix string) string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err == nil {
		// Set RFC 4122 version/variant bits. The textual form deliberately omits
		// dashes because IDs are opaque and never parsed as UUIDs.
		value[6] = (value[6] & 0x0f) | 0x40
		value[8] = (value[8] & 0x3f) | 0x80
		return prefix + "_" + hex.EncodeToString(value[:])
	}

	// crypto/rand failure is exceptional. Retain uniqueness within one daemon
	// without making callers silently drop security events.
	fallback := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", prefix, time.Now().UnixNano())))
	return prefix + "_" + hex.EncodeToString(fallback[:16])
}

// ProcessKey produces a boot-scoped stable key. A collector-provided ExecID is
// preferred. Otherwise the start/event time prevents PID reuse collisions.
func ProcessKey(bootID string, process model.Process, observedAt time.Time) string {
	material := process.ExecID
	if material == "" {
		start := process.StartTime
		if start.IsZero() {
			start = observedAt
		}
		material = strconv.Itoa(process.PID) + ":" + strconv.FormatInt(start.UnixNano(), 10)
	}
	sum := sha256.Sum256([]byte(bootID + "\x00" + material))
	return "proc_" + hex.EncodeToString(sum[:16])
}

// SourceEventID deterministically identifies one collector event so retries do
// not create duplicate durable evidence. sourceEventID must be stable within a
// boot for the selected collector.
func SourceEventID(bootID, source, eventType, sourceEventID string) string {
	sum := sha256.Sum256([]byte(bootID + "\x00" + source + "\x00" + eventType + "\x00" + sourceEventID))
	return "event_" + hex.EncodeToString(sum[:16])
}

// FindingID makes a rule result idempotent for one evidence event and rule
// version. Reprocessing an at-least-once collector delivery cannot create a
// second finding.
func FindingID(ruleID, ruleVersion, eventID string) string {
	sum := sha256.Sum256([]byte(ruleID + "\x00" + ruleVersion + "\x00" + eventID))
	return "finding_" + hex.EncodeToString(sum[:16])
}
