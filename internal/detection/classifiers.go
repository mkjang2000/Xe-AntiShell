package detection

import (
	"path/filepath"
	"strings"

	"xe-antishell/internal/model"
)

type processSignals struct {
	shell, download, recon, connection, inline, script, temporary bool
}

func (e *Engine) classify(event model.Event, origin string) processSignals {
	if !fieldAvailable(event, "process.exe") {
		return processSignals{}
	}
	if event.Type == "process.exec_observation" {
		observation := executionEvidence(event)
		return processSignals{inline: observation != nil && observation.Mode == "inline"}
	}
	name := filepath.Base(event.Process.Exe)
	_, shell := e.shells[processName(event.Process)]
	_, allowed := e.allowedPairs[origin+":"+processName(event.Process)]
	signals := processSignals{
		shell:     shell && !allowed,
		temporary: temporaryPath(event.Process.Exe, false),
	}
	switch name {
	case "curl", "wget":
		signals.download = true
	case "id", "whoami", "uname", "hostname", "ps":
		signals.recon = true
	case "nc", "ncat", "socat":
		signals.connection = true
	}
	if observation := executionEvidence(event); observation != nil {
		signals.inline = observation.Mode == "inline"
		signals.script = observation.Mode == "script"
	}
	return signals
}

// temporaryPath uses path components, not a substring of a filename. Relative
// paths and traversal resolving outside the temporary roots provide no signal.
func temporaryPath(value string, directory bool) bool {
	if !filepath.IsAbs(value) {
		return false
	}
	value = filepath.Clean(value)
	if !directory && strings.HasPrefix(value, "/memfd:") && len(value) > len("/memfd:") {
		return true
	}
	for _, root := range []string{"/tmp", "/var/tmp", "/dev/shm"} {
		if strings.HasPrefix(value, root+"/") || directory && value == root {
			return true
		}
	}
	return false
}

func fieldAvailable(event model.Event, field string) bool {
	for _, fields := range [][]string{event.MissingFields, event.TruncatedFields, event.RedactedFields} {
		for _, unavailable := range fields {
			if unavailable == "process" || unavailable == field || strings.HasPrefix(unavailable, field+".") || strings.HasPrefix(unavailable, field+"[") {
				return false
			}
			if field == "process.argv" && unavailable == "process.argv_exact" {
				return false
			}
		}
	}
	return true
}
