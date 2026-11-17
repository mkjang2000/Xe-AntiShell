package agent

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"xe-antishell/internal/detection"
	"xe-antishell/internal/identity"
	"xe-antishell/internal/model"
	"xe-antishell/internal/storage"
)

func isOperationEvent(kind string) bool {
	return kind == "process.exec_observation" || kind == "file.write" || kind == "network.connect"
}

// A source context snapshot can enrich an execution, but cannot resurrect it or
// assign a delayed operation to the current unrelated owner of the same PID.
func (s *Service) observeOperationContext(ctx context.Context, event *model.Event) error {
	observe := func(source model.Process) (model.Process, error) {
		if source.Key == "" {
			source.Key = identity.ProcessKey(event.BootID, source, event.EventTime)
		}
		if _, ok := s.lineage.Get(source.Key); !ok {
			previous, err := s.store.GetProcess(ctx, source.Key)
			if err == nil {
				s.lineage.ObserveContext(previous)
			} else if !errors.Is(err, storage.ErrNotFound) {
				return source, err
			}
		}
		if source.OriginService == "" {
			current, ok := s.lineage.CurrentByPID(source.PID)
			compatible := ok && current.Exe == source.Exe && !current.StartTime.After(source.StartTime) &&
				(current.ExecID == "" || current.ExecID == source.ExecID)
			if compatible {
				// Bootstrap has procfs identities rather than Tetragon exec IDs.
				// Adopt only attribution, and never borrow a newer PID owner's service.
				source.OriginService = current.OriginService
				if source.OriginService == "" {
					source.OriginService, _ = s.processSource.OriginService(ctx, source.PID)
				}
			}
		}
		source.Argv = nil
		source.FirstSeen, source.LastSeen = event.IngestTime, event.IngestTime
		tracked := s.lineage.ObserveContext(source)
		// Keep original credentials, cwd, executable and parent identity as evidence.
		// Only attribution/quality fields are supplied by the local context graph.
		if source.OriginService == "" {
			source.OriginService = tracked.OriginService
		}
		source.Complete = tracked.Complete
		source.LineageConfidence = tracked.LineageConfidence
		return source, nil
	}
	for index := len(event.Ancestors) - 1; index >= 0; index-- {
		value, err := observe(event.Ancestors[index])
		if err != nil {
			return err
		}
		event.Ancestors[index] = value
	}
	value, err := observe(event.Process)
	if err != nil {
		return err
	}
	event.Process = value
	return nil
}

func boundedMetadata(value string, maximum int) bool {
	return len(value) <= maximum && utf8.ValidString(value) && !strings.ContainsAny(value, "\x00\r\n")
}

func validateOperationEvent(event model.Event) error {
	count := 0
	if event.Execution != nil {
		count++
	}
	if event.File != nil {
		count++
	}
	if event.Network != nil {
		count++
	}
	if count > 1 {
		return errors.New("multiple operation payloads are not allowed")
	}
	if event.Execution != nil {
		if event.Type != "process.exec" && event.Type != "process.exec_observation" {
			return errors.New("execution proof does not match event type")
		}
		if !detection.ValidExecutionEvidence(event) {
			return errors.New("invalid or unproven execution observation")
		}
	}
	if !isOperationEvent(event.Type) {
		if event.File != nil || event.Network != nil {
			return errors.New("operation payload does not match event type")
		}
		return nil
	}
	if event.Source != "tetragon" || event.Process.PID < 1 || event.Process.ExecID == "" || event.Process.StartTime.IsZero() {
		return errors.New("operation event requires stable Tetragon execution identity")
	}
	if event.Type == "process.exec_observation" {
		if event.Execution == nil {
			return errors.New("execution observation requires typed proof")
		}
	}
	if event.Type == "file.write" {
		f := event.File
		if f == nil || f.Operation != "write" || f.PolicyName != "xeas-file-write-v1" || f.Function != "vfs_write" || !filepath.IsAbs(f.Path) || !boundedMetadata(f.Path, 4096) {
			return errors.New("invalid file write observation")
		}
		expected := "unknown"
		if f.ReturnValue != nil {
			switch {
			case *f.ReturnValue > 0:
				expected = "written"
			case *f.ReturnValue == 0:
				expected = "no_data"
			default:
				expected = "failed"
			}
		}
		if f.Outcome != expected {
			return errors.New("file write outcome contradicts return value")
		}
	}
	if event.Type == "network.connect" {
		n := event.Network
		if n == nil || n.Operation != "connect" || n.Protocol != "tcp" || n.PolicyName != "xeas-network-connect-v1" {
			return errors.New("invalid network observation")
		}
		if (n.Family != "ipv4" || n.Function != "tcp_v4_connect") && (n.Family != "ipv6" || n.Function != "tcp_v6_connect") {
			return errors.New("invalid network hook/family")
		}
		if n.DestinationAddress != "" {
			addr, err := netip.ParseAddr(n.DestinationAddress)
			if err != nil || addr.Zone() != "" || (n.Family == "ipv4" && !addr.Is4()) || (n.Family == "ipv6" && !addr.Is6()) {
				return errors.New("invalid network destination address")
			}
		}
		expected := "unknown"
		if n.ReturnValue != nil {
			if *n.ReturnValue == 0 {
				expected = "initiated"
			} else if *n.ReturnValue < 0 {
				expected = "failed"
			} else {
				return fmt.Errorf("unexpected TCP connect return value")
			}
		}
		if n.Outcome != expected {
			return errors.New("connect initiation must not imply established connection")
		}
	}
	return nil
}

// A queued event owns its typed evidence, including optional result pointers.
func cloneObservationPayloads(event *model.Event) {
	if event.Execution != nil {
		value := *event.Execution
		event.Execution = &value
	}
	if event.File != nil {
		value := *event.File
		if value.ReturnValue != nil {
			result := *value.ReturnValue
			value.ReturnValue = &result
		}
		event.File = &value
	}
	if event.Network != nil {
		value := *event.Network
		if value.ReturnValue != nil {
			result := *value.ReturnValue
			value.ReturnValue = &result
		}
		event.Network = &value
	}
}
