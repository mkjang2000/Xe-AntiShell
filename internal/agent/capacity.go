package agent

import (
	"context"
	"errors"
	"strconv"
	"sync/atomic"
	"time"

	"xe-antishell/internal/model"
	"xe-antishell/internal/storage"
)

const storageCapacity = "storage.capacity"

type dropReason uint8

const (
	dropEncode dropReason = iota
	dropOversize
	dropQueueTimeout
	dropInvalid
	dropStorage
	dropShutdown
	dropReasonCount
)

var dropNames = [dropReasonCount]string{
	dropEncode: "drop_encode", dropOversize: "drop_oversize", dropQueueTimeout: "drop_queue_timeout",
	dropInvalid: "drop_invalid", dropStorage: "drop_storage", dropShutdown: "drop_shutdown",
}

// Queue watermarks and monotonic submit-to-commit latencies span this daemon run.
type queueMetrics struct {
	highWater   atomic.Uint64
	lastLatency atomic.Uint64
	maxLatency  atomic.Uint64
	drops       [dropReasonCount]atomic.Uint64
}

func (s *Service) drop(reason dropReason, count uint64) {
	s.capacity.drops[reason].Add(count)
	s.dropped.Add(count)
}

func observeMax(counter *atomic.Uint64, value uint64) {
	for old := counter.Load(); value > old; old = counter.Load() {
		if counter.CompareAndSwap(old, value) {
			return
		}
	}
}

// Status is shared by local readers and managed heartbeats. Keep SQLite and
// filesystem sampling outside the per-observation runtime/response gate.
func (s *Service) addCapacity(ctx context.Context, report *model.CapabilityReport) {
	if s.store == nil {
		return
	}
	now := time.Now().UTC()
	depth := len(s.eventQueue)
	observeMax(&s.capacity.highWater, uint64(depth))
	historyMinutes := s.config.Limits.ObservationHistoryMinutes
	d := map[string]string{
		"queue_depth":                 strconv.Itoa(depth),
		"queue_capacity":              strconv.Itoa(cap(s.eventQueue)),
		"queue_high_water":            strconv.FormatUint(s.capacity.highWater.Load(), 10),
		"observation_history_minutes": strconv.Itoa(historyMinutes),
		"compact_observations":        strconv.FormatBool(historyMinutes > 0),
	}
	for reason, name := range dropNames {
		d[name] = strconv.FormatUint(s.capacity.drops[reason].Load(), 10)
	}
	if ns := s.capacity.lastLatency.Load(); ns > 0 {
		d["last_store_latency_ms"] = milliseconds(ns)
		d["max_store_latency_ms"] = milliseconds(s.capacity.maxLatency.Load())
	}

	value := model.Capability{Name: storageCapacity, State: model.CapabilitySupported, Provider: "sqlite",
		Implementation: "implemented", Reason: "local storage, queue and delivery capacity", Details: d, VerifiedAt: &now}
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	readings, err := s.store.Capacity(ctx, now, s.observationCutoff(now))
	if err == nil {
		addStorageDetails(d, readings)
	}
	delivery, deliveryErr := s.store.DeliveryStatus(ctx)
	if deliveryErr == nil {
		addDeliveryDetails(d, delivery)
	}
	if err != nil || (deliveryErr != nil && !errors.Is(deliveryErr, storage.ErrNotFound)) {
		value.State = model.CapabilityLimited
		value.Reason = "storage capacity sample incomplete"
	}
	report.Capabilities[storageCapacity] = value
}

func milliseconds(ns uint64) string {
	return strconv.FormatFloat(float64(ns)/float64(time.Millisecond), 'f', 3, 64)
}

func addStorageDetails(d map[string]string, c storage.CapacitySnapshot) {
	d["measurement_started_at"] = c.MeasurementStarted.Format(time.RFC3339Nano)
	d["utc_day"] = c.UTCDay
	d["stored_events_today"] = strconv.FormatInt(c.EventsToday, 10)
	d["stored_bytes_today"] = strconv.FormatInt(c.BytesToday, 10)
	if c.YesterdayObserved {
		d["stored_events_yesterday"] = strconv.FormatInt(c.EventsYesterday, 10)
		d["stored_bytes_yesterday"] = strconv.FormatInt(c.BytesYesterday, 10)
	}
	d["retention_backlog_events"] = strconv.Itoa(c.RetentionBacklog)
	d["retention_backlog_truncated"] = strconv.FormatBool(c.BacklogTruncated)
	if c.OldestEvent != nil {
		d["oldest_event_at"] = c.OldestEvent.Format(time.RFC3339Nano)
	}
	if c.DatabaseBytes != nil {
		d["database_bytes"] = strconv.FormatInt(*c.DatabaseBytes, 10)
	}
	if c.WALBytes != nil {
		d["wal_bytes"] = strconv.FormatInt(*c.WALBytes, 10)
	}
	if c.DiskAvailableBytes != nil {
		d["disk_available_bytes"] = strconv.FormatUint(*c.DiskAvailableBytes, 10)
	}
}

func addDeliveryDetails(d map[string]string, status storage.DeliveryStatus) {
	d["acknowledged"] = strconv.FormatUint(status.Acknowledged, 10)
	d["pending_records"] = strconv.Itoa(status.Pending)
	d["pending_bytes"] = strconv.FormatInt(status.PendingBytes, 10)
	d["spool_limit_bytes"] = strconv.Itoa(storage.MaxSpoolBytes)
	d["lost_records"] = strconv.FormatUint(status.LostRecords, 10)
	if status.DisconnectAt == nil {
		return
	}
	d["disconnect_at"] = status.DisconnectAt.Format(time.RFC3339Nano)
	d["outage_lost_records"] = strconv.FormatUint(status.OutageLostRecords, 10)
	if status.FirstRecoveryACKAt != nil {
		d["first_recovery_ack_at"] = status.FirstRecoveryACKAt.Format(time.RFC3339Nano)
		d["ack_recovery_seconds"] = strconv.FormatFloat(status.FirstRecoveryACKAt.Sub(*status.DisconnectAt).Seconds(), 'f', 3, 64)
	}
	if status.DrainedAt != nil {
		d["drained_at"] = status.DrainedAt.Format(time.RFC3339Nano)
		d["drain_recovery_seconds"] = strconv.FormatFloat(status.DrainedAt.Sub(*status.DisconnectAt).Seconds(), 'f', 3, 64)
	}
}
