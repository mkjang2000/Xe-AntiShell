package detection

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"xe-antishell/internal/model"
)

func protectedWriteEvent() model.Event {
	result := int64(12)
	now := time.Unix(2000, 0).UTC()
	return model.Event{
		ID: "write-one", Type: "file.write", Source: "tetragon", BootID: "boot", EventTime: now,
		Process: model.Process{Key: "writer", ExecID: "exec", PID: 35, StartTime: now.Add(-time.Hour), OriginService: "app.service"},
		File: &model.FileObservation{Operation: "write", PolicyName: "xeas-file-write-v1", Function: "vfs_write",
			Path: "/srv/app/index", Outcome: "written", ReturnValue: &result},
	}
}

func TestProtectedFileWriteScopeAndReplay(t *testing.T) {
	event := protectedWriteEvent()
	for _, tt := range []struct {
		path      string
		protected []string
		allowed   []string
		want      bool
	}{
		{"/srv/app/index", nil, nil, false},
		{"/srv/app/index", []string{"/var/www", "/srv/app"}, nil, true},
		{"/srv/application/index", []string{"/srv/app"}, nil, false},
		{"/srv/app/index", []string{"/srv/app", "/srv"}, nil, true},
		{"/srv/app/cache/index", []string{"/srv/app"}, []string{"/srv/app/upload", "/srv/app/cache"}, false},
		{"/srv/app/cache", []string{"/"}, []string{"/srv/app/cache"}, false},
		{"/srv/app/cache-v2/index", []string{"/"}, []string{"/srv/app/cache"}, true},
	} {
		event.File.Path = tt.path
		hits := evaluateProtectedFileWrite(event, tt.protected, tt.allowed)
		if !tt.want {
			if len(hits) != 0 {
				t.Errorf("unexpected finding for scope %+v", tt)
			}
			continue
		}
		if len(hits) != 1 {
			t.Fatalf("expected one finding for scope %+v, got %d", tt, len(hits))
		}
		f := hits[0]
		if f.RuleID != ruleServiceProtectedFileWrite || !f.DetectionOnly || f.RiskScore != 70 || len(f.RiskFactors) != 1 ||
			f.RiskFactors[0].ID != "protected_file_write" || f.ProcessKey != event.Process.Key || f.OriginService != event.Process.OriginService ||
			len(f.EvidenceEventIDs) != 1 || f.EvidenceEventIDs[0] != event.ID || strings.Contains(f.Summary, tt.path) {
			t.Fatalf("incorrect protected-write finding for scope %+v: %+v", tt, f)
		}
		if again := evaluateProtectedFileWrite(event, tt.protected, tt.allowed); !reflect.DeepEqual(hits, again) {
			t.Fatal("identical write replay changed finding")
		}
	}
}

func TestProtectedFileWriteRequiresPositiveProvenReturnAndCompletePath(t *testing.T) {
	for _, tt := range []struct {
		name   string
		change func(*model.Event)
	}{
		{"wrong type", func(e *model.Event) { e.Type = "process.exec" }},
		{"missing file", func(e *model.Event) { e.File = nil }},
		{"wrong source", func(e *model.Event) { e.Source = "audit" }},
		{"wrong operation", func(e *model.Event) { e.File.Operation = "open" }},
		{"permission hook", func(e *model.Event) { e.File.Function = "security_file_permission" }},
		{"unknown policy", func(e *model.Event) { e.File.PolicyName = "other" }},
		{"missing return", func(e *model.Event) { e.File.ReturnValue = nil }},
		{"failed return", func(e *model.Event) { *e.File.ReturnValue = -1 }},
		{"zero bytes", func(e *model.Event) { *e.File.ReturnValue = 0 }},
		{"unknown outcome", func(e *model.Event) { e.File.Outcome = "unknown" }},
		{"positive failure", func(e *model.Event) { e.File.Outcome = "failed" }},
		{"relative", func(e *model.Event) { e.File.Path = "srv/app/index" }},
		{"traversal", func(e *model.Event) { e.File.Path = "/srv/app/../index" }},
		{"unclean", func(e *model.Event) { e.File.Path = "/srv/app//index" }},
		{"control", func(e *model.Event) { e.File.Path = "/srv/app/index\n" }},
		{"long path", func(e *model.Event) { e.File.Path = "/srv/app/" + strings.Repeat("x", 4096) }},
		{"path loss", func(e *model.Event) { e.TruncatedFields = []string{"file.path"} }},
		{"whole file loss", func(e *model.Event) { e.MissingFields = []string{"file"} }},
		{"redacted proof", func(e *model.Event) { e.RedactedFields = []string{"file.return_value"} }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			event := protectedWriteEvent()
			tt.change(&event)
			if hits := evaluateProtectedFileWrite(event, []string{"/srv/app"}, nil); len(hits) != 0 {
				t.Fatal("accepted unconfirmed write")
			}
		})
	}
}
