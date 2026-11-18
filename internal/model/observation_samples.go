package model

import (
	"errors"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	shared "github.com/mkjang2000/Xe-AntiShell/protocol/model"
)

type ObservationQuery struct {
	Limit        int
	Service      string
	ProtectedDir string
	AllowedDir   string
}

type ObservationReport struct {
	Samples []ObservationSample `json:"samples"`
}

// ObservationSample exposes the source result and the service attributed at
// collection time, independent of the current owner of a reused PID.
type ObservationSample struct {
	EventID            string    `json:"event_id"`
	EventTime          time.Time `json:"event_time"`
	EventType          string    `json:"event_type"`
	Service            string    `json:"service"`
	Outcome            string    `json:"outcome"`
	Path               string    `json:"path,omitempty"`
	DestinationAddress string    `json:"destination_address,omitempty"`
	DestinationPort    uint16    `json:"destination_port,omitempty"`
	ReturnValue        *int64    `json:"return_value,omitempty"`
	Review             string    `json:"review,omitempty"`
}

func ParseObservationQuery(values url.Values) (ObservationQuery, error) {
	q := ObservationQuery{Service: values.Get("service"), ProtectedDir: values.Get("protected_dir"), AllowedDir: values.Get("allowed_dir"), Limit: 20}
	if values.Has("limit") {
		n, err := strconv.Atoi(values.Get("limit"))
		if err != nil || n == 0 {
			return q, errors.New("limit must be 1 through 100")
		}
		q.Limit = n
	}
	return q, q.Validate()
}

func (q ObservationQuery) Validate() error {
	if q.Limit < 0 || q.Limit > 100 {
		return errors.New("limit must be 1 through 100")
	}
	if len(q.Service) > 512 || !utf8.ValidString(q.Service) || strings.IndexFunc(q.Service, unicode.IsControl) >= 0 {
		return errors.New("invalid service")
	}
	if q.AllowedDir != "" && q.ProtectedDir == "" {
		return errors.New("allowed_dir requires protected_dir")
	}
	if q.ProtectedDir != "" && (q.Service == "" || q.Service == "unknown") {
		return errors.New("path review requires an attributed service")
	}
	for _, dir := range []string{q.ProtectedDir, q.AllowedDir} {
		if dir != "" && !CleanObservationPath(dir) {
			return errors.New("review directories must be clean absolute Linux paths")
		}
	}
	return nil
}

// ReviewFile considers only the observed path and return value. It never
// resolves a symlink against the operator's current host filesystem.
func (q ObservationQuery) ReviewFile(s ObservationSample) string {
	if q.ProtectedDir == "" || s.EventType != "file.write" || s.Service != q.Service {
		return ""
	}
	if !ConfirmedFileWrite(s.Path, s.Outcome, s.ReturnValue) {
		return "unconfirmed_write"
	}
	if WithinObservationDirectory(s.Path, q.AllowedDir) {
		return "allowed_path"
	}
	if WithinObservationDirectory(s.Path, q.ProtectedDir) {
		return "protected_write_candidate"
	}
	return "outside_protected_path"
}

// CleanObservationPath accepts complete, absolute Linux paths as recorded.
func CleanObservationPath(value string) bool {
	return shared.CleanObservationPath(value)
}

func ConfirmedFileWrite(value, outcome string, result *int64) bool {
	return outcome == "written" && result != nil && *result > 0 && CleanObservationPath(value)
}

// WithinObservationDirectory compares validated paths lexically, at a component
// boundary. It works for "/" and never resolves paths on the current host.
func WithinObservationDirectory(value, dir string) bool {
	return shared.WithinObservationDirectory(value, dir)
}
