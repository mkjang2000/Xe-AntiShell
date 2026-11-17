package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"xe-antishell/internal/model"
)

const selfTestService = "xeas-detection-selftest.service"

// Prefer explicit service attribution over legacy summary text. A finding
// attributed to another service must not disappear because its text happens
// to mention the self-test service name.
const findingSelfTestSQL = `(COALESCE(NULLIF(json_extract(f.finding_json,'$.origin_service'),''),NULLIF(p.origin_service,''),'') = ?
OR (COALESCE(NULLIF(json_extract(f.finding_json,'$.origin_service'),''),NULLIF(p.origin_service,''),'') IN ('','unknown')
AND instr(COALESCE(json_extract(f.finding_json,'$.summary'),''),?) > 0))`

// OperatorSummary takes one SQLite statement snapshot so finding classifications
// and totals remain internally consistent while the collector accepts events.
func (s *Store) OperatorSummary(ctx context.Context, now time.Time) (model.OperatorSummary, error) {
	now = now.UTC()
	result := model.OperatorSummary{AsOf: now, WindowStart: now.Add(-24 * time.Hour)}
	var recent []byte
	err := s.db.QueryRowContext(ctx, `WITH classified AS (
SELECT f.finding_id,f.finding_json,f.created_at_ns,f.state,f.severity,
COALESCE(NULLIF(json_extract(f.finding_json,'$.origin_service'),''),NULLIF(p.origin_service,''),'unknown') AS origin_service,
`+findingSelfTestSQL+` AS self_test
FROM findings f LEFT JOIN processes p ON p.process_key=f.process_key
), finding_counts AS (
SELECT count(*) FILTER(WHERE NOT self_test),
count(*) FILTER(WHERE NOT self_test AND state='open'),
count(*) FILTER(WHERE NOT self_test AND created_at_ns>=? AND created_at_ns<=?),
count(*) FILTER(WHERE self_test),
count(*) FILTER(WHERE NOT self_test AND state='open' AND severity='critical'),
count(*) FILTER(WHERE NOT self_test AND state='open' AND severity='high'),
count(*) FILTER(WHERE NOT self_test AND state='open' AND severity NOT IN ('critical','high'))
FROM classified
)
SELECT (SELECT count(*) FROM events),
(SELECT count(*) FROM events WHERE event_time_ns>=? AND event_time_ns<=?),*,
(SELECT json_group_array(json(payload)) FROM (
SELECT json_set(finding_json,'$.origin_service',origin_service) AS payload
FROM classified WHERE NOT self_test ORDER BY created_at_ns DESC,finding_id DESC LIMIT 5))
FROM finding_counts`, selfTestService, selfTestService, result.WindowStart.UnixNano(), now.UnixNano(), result.WindowStart.UnixNano(), now.UnixNano()).Scan(
		&result.TotalEvents, &result.Events24H, &result.TotalFindings, &result.OpenFindings,
		&result.Findings24H, &result.SelfTestFindings, &result.CriticalOpen, &result.HighOpen, &result.OtherOpen,
		&recent,
	)
	if err != nil {
		return model.OperatorSummary{}, fmt.Errorf("operator summary: %w", err)
	}
	if err := json.Unmarshal(recent, &result.RecentFindings); err != nil {
		return model.OperatorSummary{}, fmt.Errorf("operator summary findings: %w", err)
	}
	return result, nil
}
