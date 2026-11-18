package storage

import (
	"crypto/sha256"
	"encoding/json"

	"xe-antishell/internal/model"
)

// The digest covers the input before any persistence-only projection. Stable
// source events use the same retry equivalence as legacy complete rows.
func observationDigest(event model.Event) ([]byte, error) {
	if event.SourceEventID != "" {
		event = comparableSourceEvent(event)
	}
	body, err := json.Marshal(event)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(body)
	return digest[:], nil
}

func compactObservation(event model.Event) model.Event {
	event.RawJSON = nil
	event.Ancestors = nil
	event.Process = compactProcess(event.Process)
	return event
}

func compactProcess(process model.Process) model.Process {
	process.Argv = nil
	process.CWD = ""
	return process
}
