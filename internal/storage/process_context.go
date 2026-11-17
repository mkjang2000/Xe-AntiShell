package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"xe-antishell/internal/model"
)

// saveProcessContext enriches a projection without treating an operation as a
// new exec. Durable lifecycle state remains authoritative after cache eviction.
func (s *Store) saveProcessContext(ctx context.Context, bootID string, incoming model.Process) error {
	if incoming.FirstSeen.IsZero() || incoming.LastSeen.IsZero() || incoming.LastSeen.Before(incoming.FirstSeen) {
		return errors.New("storage: invalid process context observation bounds")
	}
	var storedBoot string
	var raw []byte
	err := s.executor().QueryRowContext(ctx, "SELECT boot_id,process_json FROM processes WHERE process_key=?", incoming.Key).Scan(&storedBoot, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return s.SaveProcess(ctx, bootID, incoming)
	}
	if err != nil {
		return fmt.Errorf("storage: read process context: %w", err)
	}
	previous, err := decodeProcess(raw)
	if err != nil {
		return err
	}
	sameExecution := previous.ExecID != "" && previous.ExecID == incoming.ExecID
	if storedBoot != bootID || previous.PID != incoming.PID || (!sameExecution && (previous.ExecID != incoming.ExecID || !previous.StartTime.Equal(incoming.StartTime))) {
		return fmt.Errorf("%w: incompatible process context identity", ErrConflict)
	}
	if incoming.FirstSeen.Before(previous.FirstSeen) {
		previous.FirstSeen = incoming.FirstSeen
	}
	if incoming.LastSeen.After(previous.LastSeen) {
		previous.LastSeen = incoming.LastSeen
	}
	if previous.OriginService == "" {
		previous.OriginService = incoming.OriginService
	}
	if previous.ParentKey == "" {
		previous.ParentKey = incoming.ParentKey
	}
	if previous.ExitedAt == nil && incoming.ExitedAt != nil {
		previous.ExitedAt = incoming.ExitedAt
	}
	return s.SaveProcess(ctx, bootID, previous)
}
