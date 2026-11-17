package storage

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"xe-antishell/internal/model"
)

const unknownService = "unknown"

const findingRuleTitleSQL = `CASE f.rule_id
WHEN 'web-descendant-root-shell' THEN '웹 서비스에서 관리자 권한 셸 실행'
WHEN 'web-descendant-shell' THEN '웹 서비스에서 셸 실행'
WHEN 'web-descendant-download-tool' THEN '웹 서비스에서 다운로드 도구 실행'
WHEN 'web-descendant-recon-tool' THEN '웹 서비스에서 정보 확인 도구 실행'
WHEN 'web-descendant-connection-tool' THEN '웹 서비스에서 연결 도구 실행'
WHEN 'web-descendant-inline-interpreter' THEN '웹 서비스에서 직접 코드 실행 요청'
WHEN 'web-descendant-temporary-executable' THEN '웹 서비스에서 임시 경로의 실행 파일 실행'
ELSE '' END`

type historyCursor struct {
	Time  int64  `json:"t"`
	ID    string `json:"i"`
	Scope string `json:"s"`
}

func (s *Store) History(ctx context.Context, q model.HistoryQuery) (model.HistoryPage, error) {
	if q.Kind != "events" && q.Kind != "findings" {
		return model.HistoryPage{}, errors.New("kind must be events or findings")
	}
	if q.Limit == 0 {
		q.Limit = 10
	}
	if q.Limit < 1 || q.Limit > 100 || len(q.Search) > 256 || len(q.Service) > 512 || len(q.Cursor) > 2048 {
		return model.HistoryPage{}, errors.New("invalid history query bounds")
	}
	if q.Severity != "" && q.Severity != "all" && q.Severity != "critical" && q.Severity != "high" && q.Severity != "medium" && q.Severity != "low" {
		return model.HistoryPage{}, errors.New("invalid severity")
	}
	var from, id, at, body, service string
	if q.Kind == "events" {
		from = "events e"
		id, at, body = "e.event_id", "e.event_time_ns", "e.event_json"
		service = "COALESCE(NULLIF(json_extract(e.event_json,'$.process.origin_service'),''),'unknown')"
	} else {
		from = "findings f LEFT JOIN processes p ON p.process_key=f.process_key"
		id, at, body = "f.finding_id", "f.created_at_ns", "f.finding_json"
		service = "COALESCE(NULLIF(json_extract(f.finding_json,'$.origin_service'),''),NULLIF(p.origin_service,''),'unknown')"
	}
	var conditions []string
	var args []any
	if q.Kind == "findings" && q.ExcludeSelfTests {
		conditions = append(conditions, "NOT "+findingSelfTestSQL)
		args = append(args, selfTestService, selfTestService)
	}
	if q.Service != "" && q.Service != "all" {
		conditions = append(conditions, service+" = ?")
		args = append(args, q.Service)
	}
	if q.Search != "" {
		if q.Kind == "findings" {
			// Include the operator-facing rule title and retained process path.
			// Raw evidence remains searchable for unknown/future rule versions.
			conditions = append(conditions, "(instr(lower("+body+"),lower(?)) > 0 OR instr(lower(COALESCE(p.exe,'')),lower(?)) > 0 OR instr("+findingRuleTitleSQL+",?) > 0)")
			args = append(args, q.Search, q.Search, q.Search)
		} else {
			conditions = append(conditions, "instr(lower("+body+"),lower(?)) > 0")
			args = append(args, q.Search)
		}
	}
	if q.Kind == "findings" && q.Severity != "" && q.Severity != "all" {
		conditions = append(conditions, "f.severity = ?")
		args = append(args, q.Severity)
	}
	where := " WHERE 1=1"
	if len(conditions) > 0 {
		where += " AND " + strings.Join(conditions, " AND ")
	}
	var page model.HistoryPage
	if err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM "+from+where, args...).Scan(&page.Total); err != nil {
		return page, err
	}
	scopeInput := q
	scopeInput.Cursor = ""
	scopeInput.Limit = 0
	scopeJSON, _ := json.Marshal(scopeInput)
	digest := sha256.Sum256(scopeJSON)
	scope := hex.EncodeToString(digest[:8])
	if q.Cursor != "" {
		data, err := base64.RawURLEncoding.DecodeString(q.Cursor)
		if err != nil {
			return page, errors.New("invalid history cursor")
		}
		var cursor historyCursor
		if json.Unmarshal(data, &cursor) != nil || cursor.Scope != scope || cursor.Time <= 0 || cursor.ID == "" {
			return page, errors.New("history cursor does not match filters")
		}
		where += " AND (" + at + " < ? OR (" + at + " = ? AND " + id + " < ?))"
		args = append(args, cursor.Time, cursor.Time, cursor.ID)
	}
	args = append(args, q.Limit+1)
	rows, err := s.db.QueryContext(ctx, "SELECT "+body+","+at+","+id+","+service+" FROM "+from+where+" ORDER BY "+at+" DESC,"+id+" DESC LIMIT ?", args...)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	items := make([]json.RawMessage, 0, q.Limit)
	var last historyCursor
	for rows.Next() {
		var raw []byte
		var timestamp int64
		var itemID, origin string
		if err := rows.Scan(&raw, &timestamp, &itemID, &origin); err != nil {
			return page, err
		}
		if len(items) == q.Limit {
			page.HasMore = true
			break
		}
		if q.Kind == "findings" {
			var finding model.Finding
			if err := json.Unmarshal(raw, &finding); err != nil {
				return page, err
			}
			finding.OriginService = origin
			raw, _ = json.Marshal(finding)
		}
		items = append(items, json.RawMessage(raw))
		last = historyCursor{Time: timestamp, ID: itemID, Scope: scope}
	}
	if err := rows.Err(); err != nil {
		return page, err
	}
	page.Items, _ = json.Marshal(items)
	if page.HasMore {
		data, _ := json.Marshal(last)
		page.NextCursor = base64.RawURLEncoding.EncodeToString(data)
	}
	return page, nil
}

func (s *Store) Services(ctx context.Context) ([]model.ServiceSummary, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT name,sum(fc),sum(ec) FROM (
SELECT COALESCE(NULLIF(json_extract(e.event_json,'$.process.origin_service'),''),'unknown') name,0 fc,count(*) ec FROM events e GROUP BY name
UNION ALL
SELECT COALESCE(NULLIF(json_extract(f.finding_json,'$.origin_service'),''),NULLIF(p.origin_service,''),'unknown') name,count(*) fc,0 ec FROM findings f LEFT JOIN processes p ON p.process_key=f.process_key GROUP BY name
) GROUP BY name ORDER BY sum(fc) DESC,name LIMIT 1000`)
	if err != nil {
		return nil, fmt.Errorf("service history: %w", err)
	}
	defer rows.Close()
	result := make([]model.ServiceSummary, 0)
	for rows.Next() {
		var row model.ServiceSummary
		if err := rows.Scan(&row.Name, &row.FindingCount, &row.EventCount); err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}
