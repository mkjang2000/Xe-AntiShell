// Package managed defines the bounded central-agent protocol and independent
// policy/removal authorization primitives. It does not execute response actions.
package managed

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/model"
)

const (
	SchemaVersion         = "1"
	MaxBatchRecords       = 256
	MaxRecordBytes        = 1 << 20
	MaxPolicyBytes        = 64 << 10
	MaxHeartbeatBytes     = 1 << 20
	RecordKindEvent       = "event"
	RecordKindFinding     = "finding"
	RecordKindAudit       = "audit"
	RecordKindEventBundle = "event_bundle"
)

type Record struct {
	Sequence uint64          `json:"sequence"`
	Kind     string          `json:"kind"`
	ID       string          `json:"id"`
	Payload  json.RawMessage `json:"payload"`
}

type Batch struct {
	EnrollmentID string   `json:"enrollment_id"`
	SpoolID      string   `json:"spool_id"`
	Records      []Record `json:"records"`
}

type Ack struct {
	SpoolID      string `json:"spool_id"`
	Acknowledged uint64 `json:"acknowledged"`
}

type EventBundle struct {
	Event    model.Event     `json:"event"`
	Findings []model.Finding `json:"findings"`
}

type AuditRecord struct {
	ID          string            `json:"id"`
	Action      string            `json:"action"`
	OperationID string            `json:"operation_id,omitempty"`
	OccurredAt  time.Time         `json:"occurred_at"`
	Result      string            `json:"result"`
	Details     map[string]string `json:"details,omitempty"`
}

type EnrollRequest struct {
	AgentID  string `json:"agent_id"`
	CSRPEM   string `json:"csr_pem"`
	Hostname string `json:"hostname,omitempty"`
}

type EnrollResponse struct {
	AgentID         string `json:"agent_id"`
	EnrollmentID    string `json:"enrollment_id"`
	CertificatePEM  string `json:"certificate_pem"`
	CAPEM           string `json:"ca_pem"`
	PolicyKeyID     string `json:"policy_key_id"`
	PolicyPublicKey string `json:"policy_public_key"`
}

type PolicyStatus struct {
	DesiredRevision uint64     `json:"desired_revision"`
	ActiveRevision  uint64     `json:"active_revision"`
	Result          string     `json:"result"`
	Error           string     `json:"error,omitempty"`
	AppliedAt       *time.Time `json:"applied_at,omitempty"`
}

type Heartbeat struct {
	AgentID        string            `json:"agent_id"`
	EnrollmentID   string            `json:"enrollment_id"`
	Hostname       string            `json:"hostname"`
	SentAt         time.Time         `json:"sent_at"`
	Status         model.AgentStatus `json:"status"`
	Resources      json.RawMessage   `json:"resources,omitempty"`
	PolicyStatus   PolicyStatus      `json:"policy_status"`
	PolicyRevision uint64            `json:"policy_revision,omitempty"`
	PolicyError    string            `json:"policy_error,omitempty"`
}

func (r Record) Validate() error {
	if r.Sequence < 1 || r.Sequence > math.MaxInt64 || !validIdentifier(r.ID, 160) {
		return errors.New("invalid delivery sequence or record ID")
	}
	switch r.Kind {
	case RecordKindEvent, RecordKindFinding, RecordKindAudit, RecordKindEventBundle:
	default:
		return errors.New("unsupported delivery record kind")
	}
	if len(r.Payload) == 0 || len(r.Payload) > MaxRecordBytes || !json.Valid(r.Payload) || bytes.Equal(bytes.TrimSpace(r.Payload), []byte("null")) {
		return errors.New("invalid or oversized delivery payload")
	}
	if bytes.TrimSpace(r.Payload)[0] != '{' {
		return errors.New("delivery payload must be a JSON object")
	}
	return nil
}

func (b Batch) Validate() error {
	if !validIdentifier(b.EnrollmentID, 160) || !validIdentifier(b.SpoolID, 160) || len(b.Records) < 1 || len(b.Records) > MaxBatchRecords {
		return errors.New("invalid delivery batch identity or size")
	}
	for index, record := range b.Records {
		if err := record.Validate(); err != nil {
			return fmt.Errorf("record %d: %w", index, err)
		}
		if index > 0 && record.Sequence != b.Records[index-1].Sequence+1 {
			return errors.New("delivery sequences must be contiguous within a batch")
		}
	}
	return nil
}

// DecodeStrict prevents silently accepting privileged or unsupported policy
// fields. Callers must also apply their transport body limit before decoding.
func DecodeStrict(data []byte, maximum int, output any) error {
	if len(data) == 0 || maximum < 1 || len(data) > maximum {
		return errors.New("JSON input is empty or exceeds its limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("JSON input contains trailing data")
	}
	return nil
}

func validIdentifier(value string, maximum int) bool {
	if value == "" || len(value) > maximum {
		return false
	}
	for _, char := range value {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '-' || char == '_' || char == '.' || char == ':') {
			return false
		}
	}
	return true
}
