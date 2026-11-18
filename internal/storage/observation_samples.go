package storage

import (
	"context"
	"encoding/json"

	"xe-antishell/internal/model"
)

const observationSamplesByService = `SELECT e.event_json
FROM observation_services s JOIN events e ON e.event_id=s.event_id
WHERE s.service=?
ORDER BY s.event_time_ns DESC,s.event_id DESC LIMIT ?`

func (s *Store) ObservationSamples(ctx context.Context, q model.ObservationQuery) (model.ObservationReport, error) {
	result := model.ObservationReport{Samples: []model.ObservationSample{}}
	if err := q.Validate(); err != nil {
		return result, err
	}
	limit := q.Limit
	if limit == 0 {
		limit = 20
	}

	// Unfiltered reads merge the two event-type indexes. Scoped reads can
	// fetch event payloads in the service/time index order.
	const ordered = " ORDER BY event_time_ns DESC,event_id DESC LIMIT ?"
	stmt := "SELECT event_json FROM (" +
		"SELECT event_json,event_time_ns,event_id FROM events WHERE event_type='file.write'" +
		" UNION ALL SELECT event_json,event_time_ns,event_id FROM events WHERE event_type='network.connect'" +
		ordered + ")"
	args := []any{limit}
	if q.Service != "" {
		stmt = observationSamplesByService
		args = []any{q.Service, limit}
	}
	rows, err := s.db.QueryContext(ctx, stmt, args...)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return result, err
		}
		var e model.Event
		if err := json.Unmarshal(raw, &e); err != nil {
			return result, err
		}
		sample := model.ObservationSample{EventID: e.ID, EventTime: e.EventTime, EventType: e.Type, Service: e.Process.OriginService, Outcome: "unknown"}
		if sample.Service == "" {
			sample.Service = unknownService
		}
		switch {
		case e.Type == "file.write" && e.File != nil:
			sample.Path, sample.ReturnValue = e.File.Path, e.File.ReturnValue
			if e.File.Outcome != "" {
				sample.Outcome = e.File.Outcome
			}
		case e.Type == "network.connect" && e.Network != nil:
			sample.DestinationAddress, sample.DestinationPort, sample.ReturnValue = e.Network.DestinationAddress, e.Network.DestinationPort, e.Network.ReturnValue
			if e.Network.Outcome != "" {
				sample.Outcome = e.Network.Outcome
			}
		}
		sample.Review = q.ReviewFile(sample)
		result.Samples = append(result.Samples, sample)
	}
	return result, rows.Err()
}
