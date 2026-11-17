package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"xe-antishell/internal/model"
)

// FindingFilter bounds a newest-first finding query.
type FindingFilter struct {
	Severity   string
	State      string
	ProcessKey string
	After      time.Time
	Before     time.Time
	Limit      int
}

// SaveFinding saves a finding and atomically replaces its ordered evidence
// links. Every evidence event must already be durable.
func (s *Store) SaveFinding(ctx context.Context, finding model.Finding) error {
	if finding.ID == "" || finding.RuleID == "" {
		return errors.New("storage: finding ID and rule ID are required")
	}
	if finding.CreatedAt.IsZero() {
		return errors.New("storage: finding creation time is required")
	}
	if finding.Severity == "" || finding.State == "" {
		return errors.New("storage: finding severity and state are required")
	}
	if finding.Confidence < 0 || finding.Confidence > 1 {
		return errors.New("storage: finding confidence must be between 0 and 1")
	}
	if len(finding.EvidenceEventIDs) == 0 {
		return errors.New("storage: finding requires at least one evidence event")
	}
	if duplicate := firstDuplicate(finding.EvidenceEventIDs); duplicate != "" {
		return fmt.Errorf("storage: finding contains duplicate evidence event %q", duplicate)
	}

	body, err := json.Marshal(finding)
	if err != nil {
		return fmt.Errorf("storage: encode finding %q: %w", finding.ID, err)
	}
	tx := s.tx
	owned := tx == nil
	if owned {
		var err error
		tx, err = s.db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("storage: begin finding save: %w", err)
		}
		defer func() { _ = tx.Rollback() }()
	}

	if _, err := tx.ExecContext(ctx, `
INSERT INTO findings(
    finding_id, rule_id, rule_version, created_at_ns, severity, confidence,
    state, process_key, source, finding_json
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(finding_id) DO UPDATE SET
    rule_id = excluded.rule_id,
    rule_version = excluded.rule_version,
    created_at_ns = excluded.created_at_ns,
    severity = excluded.severity,
    confidence = excluded.confidence,
    state = excluded.state,
    process_key = excluded.process_key,
    source = excluded.source,
    finding_json = excluded.finding_json`,
		finding.ID, finding.RuleID, finding.RuleVersion, finding.CreatedAt.UnixNano(),
		finding.Severity, finding.Confidence, finding.State, finding.ProcessKey,
		finding.Source, body,
	); err != nil {
		return fmt.Errorf("storage: upsert finding %q: %w", finding.ID, err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM finding_events WHERE finding_id = ?`, finding.ID); err != nil {
		return fmt.Errorf("storage: replace evidence for finding %q: %w", finding.ID, err)
	}
	for index, eventID := range finding.EvidenceEventIDs {
		if eventID == "" {
			return errors.New("storage: finding evidence event ID is empty")
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO finding_events(finding_id, event_id, position) VALUES (?, ?, ?)`,
			finding.ID, eventID, index,
		); err != nil {
			return fmt.Errorf("storage: link evidence event %q to finding %q: %w", eventID, finding.ID, err)
		}
	}
	if owned {
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("storage: commit finding %q: %w", finding.ID, err)
		}
	}
	return nil
}

// GetFinding returns a finding and its ordered durable evidence links.
func (s *Store) GetFinding(ctx context.Context, findingID string) (model.Finding, error) {
	var body []byte
	err := s.db.QueryRowContext(ctx, `SELECT finding_json FROM findings WHERE finding_id = ?`, findingID).Scan(&body)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Finding{}, fmt.Errorf("%w: finding %q", ErrNotFound, findingID)
	}
	if err != nil {
		return model.Finding{}, fmt.Errorf("storage: get finding %q: %w", findingID, err)
	}
	finding, err := decodeFinding(body)
	if err != nil {
		return model.Finding{}, err
	}
	evidence, err := s.findingEvidence(ctx, findingID)
	if err != nil {
		return model.Finding{}, err
	}
	finding.EvidenceEventIDs = evidence
	return finding, nil
}

// ListFindings returns matching findings newest first.
func (s *Store) ListFindings(ctx context.Context, filter FindingFilter) ([]model.Finding, error) {
	limit, err := boundedLimit(filter.Limit)
	if err != nil {
		return nil, err
	}

	var query strings.Builder
	query.WriteString(`SELECT finding_id, finding_json FROM findings WHERE 1 = 1`)
	args := make([]any, 0, 6)
	if filter.Severity != "" {
		query.WriteString(` AND severity = ?`)
		args = append(args, filter.Severity)
	}
	if filter.State != "" {
		query.WriteString(` AND state = ?`)
		args = append(args, filter.State)
	}
	if filter.ProcessKey != "" {
		query.WriteString(` AND process_key = ?`)
		args = append(args, filter.ProcessKey)
	}
	if !filter.After.IsZero() {
		query.WriteString(` AND created_at_ns >= ?`)
		args = append(args, filter.After.UnixNano())
	}
	if !filter.Before.IsZero() {
		query.WriteString(` AND created_at_ns < ?`)
		args = append(args, filter.Before.UnixNano())
	}
	query.WriteString(` ORDER BY created_at_ns DESC, finding_id DESC LIMIT ?`)
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, query.String(), args...)
	if err != nil {
		return nil, fmt.Errorf("storage: list findings: %w", err)
	}
	type encodedFinding struct {
		id   string
		body []byte
	}
	encoded := make([]encodedFinding, 0)
	for rows.Next() {
		var item encodedFinding
		if err := rows.Scan(&item.id, &item.body); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("storage: scan finding: %w", err)
		}
		encoded = append(encoded, item)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("storage: close finding rows: %w", err)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("storage: iterate findings: %w", err)
	}

	findings := make([]model.Finding, 0, len(encoded))
	for _, item := range encoded {
		finding, err := decodeFinding(item.body)
		if err != nil {
			return nil, err
		}
		evidence, err := s.findingEvidence(ctx, item.id)
		if err != nil {
			return nil, err
		}
		finding.EvidenceEventIDs = evidence
		findings = append(findings, finding)
	}
	return findings, nil
}

func (s *Store) findingEvidence(ctx context.Context, findingID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT event_id FROM finding_events WHERE finding_id = ? ORDER BY position`, findingID)
	if err != nil {
		return nil, fmt.Errorf("storage: read finding evidence: %w", err)
	}
	defer rows.Close()
	evidence := make([]string, 0)
	for rows.Next() {
		var eventID string
		if err := rows.Scan(&eventID); err != nil {
			return nil, fmt.Errorf("storage: scan finding evidence: %w", err)
		}
		evidence = append(evidence, eventID)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("storage: iterate finding evidence: %w", err)
	}
	return evidence, nil
}

func decodeFinding(body []byte) (model.Finding, error) {
	var finding model.Finding
	if err := json.Unmarshal(body, &finding); err != nil {
		return model.Finding{}, fmt.Errorf("storage: decode stored finding: %w", err)
	}
	return finding, nil
}

func firstDuplicate(values []string) string {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			return value
		}
		seen[value] = struct{}{}
	}
	return ""
}
