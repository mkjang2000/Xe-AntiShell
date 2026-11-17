package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"xe-antishell/internal/model"
)

// SaveCapabilityReport appends a capability snapshot. Reports are historical;
// callers obtain the current view through LatestCapabilityReport.
func (s *Store) SaveCapabilityReport(ctx context.Context, report model.CapabilityReport) error {
	if report.ProbeVersion == "" {
		return errors.New("storage: capability probe version is required")
	}
	if report.ProbedAt.IsZero() {
		return errors.New("storage: capability probe time is required")
	}
	body, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("storage: encode capability report: %w", err)
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO capability_reports(observed_at_ns, report_json) VALUES (?, ?)`,
		report.ProbedAt.UnixNano(), body,
	); err != nil {
		return fmt.Errorf("storage: save capability report: %w", err)
	}
	return nil
}

// LatestCapabilityReport returns the most recently probed report.
func (s *Store) LatestCapabilityReport(ctx context.Context) (model.CapabilityReport, error) {
	var body []byte
	err := s.db.QueryRowContext(ctx, `
SELECT report_json
FROM capability_reports
ORDER BY observed_at_ns DESC, report_id DESC
LIMIT 1`).Scan(&body)
	if errors.Is(err, sql.ErrNoRows) {
		return model.CapabilityReport{}, fmt.Errorf("%w: capability report", ErrNotFound)
	}
	if err != nil {
		return model.CapabilityReport{}, fmt.Errorf("storage: get latest capability report: %w", err)
	}
	var report model.CapabilityReport
	if err := json.Unmarshal(body, &report); err != nil {
		return model.CapabilityReport{}, fmt.Errorf("storage: decode capability report: %w", err)
	}
	return report, nil
}
