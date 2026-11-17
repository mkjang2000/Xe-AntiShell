package detection

import (
	"path/filepath"
	"strings"

	"xe-antishell/internal/model"
)

type processSignals struct {
	shell, download, recon, connection, inline, temporary bool
}

func (e *Engine) classify(event model.Event, origin string) processSignals {
	if !fieldAvailable(event, "process.exe") {
		return processSignals{}
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
	signals.inline = inlineInterpreter(event, name)
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

type interpreterOptions struct {
	inlineFlags  []string
	switches     []string
	valuedFlags  []string
	joinedValues []string
}

// Only explicit inline-code options before a script/module boundary qualify.
// The code itself is never inspected or included in finding metadata.
func inlineInterpreter(event model.Event, name string) bool {
	if strings.EqualFold(event.Source, "tetragon") || !fieldAvailable(event, "process.argv") || len(event.Process.Argv) < 3 {
		return false
	}
	// Incomplete audit groups cannot establish original argument boundaries,
	// even when the remaining records happen to contain an inline option.
	if !fieldAvailable(event, "audit.records") || !fieldAvailable(event, "audit.EOE") {
		return false
	}
	options, supported := interpreterOptionSet(name)
	if !supported {
		return false
	}
	args := event.Process.Argv[1:]
	for i := 0; i < len(args); i++ {
		argument := args[i]
		if stringIn(argument, options.inlineFlags) {
			return i+1 < len(args) && strings.TrimSpace(args[i+1]) != ""
		}
		if stringIn(argument, options.switches) {
			continue
		}
		if stringIn(argument, options.valuedFlags) {
			if i+1 >= len(args) {
				return false
			}
			i++
			continue
		}
		joined := false
		for _, prefix := range options.joinedValues {
			if strings.HasPrefix(argument, prefix) && len(argument) > len(prefix) {
				joined = true
				break
			}
		}
		if !joined {
			// Includes script filenames, --, module flags and unsupported options.
			return false
		}
	}
	return false
}

func interpreterOptionSet(name string) (interpreterOptions, bool) {
	switch {
	case versionedInterpreter(name, "python"):
		return interpreterOptions{
			inlineFlags: []string{"-c"},
			switches:    []string{"-B", "-E", "-I", "-O", "-OO", "-P", "-q", "-s", "-S", "-u", "-v", "-x", "-b", "-bb", "-d"},
			valuedFlags: []string{"-W", "-X", "--check-hash-based-pycs"}, joinedValues: []string{"-W", "-X"},
		}, true
	case versionedInterpreter(name, "node"), versionedInterpreter(name, "nodejs"):
		return interpreterOptions{
			inlineFlags:  []string{"-e", "--eval"},
			switches:     []string{"--no-warnings", "--trace-warnings", "--use-strict"},
			valuedFlags:  []string{"-r", "--require", "--loader", "--import", "--input-type"},
			joinedValues: []string{"-r", "--require=", "--loader=", "--import=", "--input-type="},
		}, true
	case versionedInterpreter(name, "perl"):
		return interpreterOptions{
			inlineFlags: []string{"-e"}, switches: []string{"-w", "-W", "-T", "-t", "-s", "-n", "-p", "-l", "-a"},
			valuedFlags: []string{"-M", "-m", "-I", "-F"}, joinedValues: []string{"-M", "-m", "-I", "-F"},
		}, true
	case versionedInterpreter(name, "php"):
		return interpreterOptions{
			inlineFlags: []string{"-r"}, switches: []string{"-n", "-q", "-C"},
			valuedFlags: []string{"-d", "-c"}, joinedValues: []string{"-d", "-c"},
		}, true
	case versionedInterpreter(name, "ruby"):
		return interpreterOptions{
			inlineFlags: []string{"-e"}, switches: []string{"-w", "-W0", "-W1", "-W2", "-d", "-v", "-n", "-p", "-a", "-l", "-s", "--disable-gems"},
			valuedFlags: []string{"-I", "-r", "-E", "--encoding"}, joinedValues: []string{"-I", "-r", "-E", "--encoding="},
		}, true
	default:
		return interpreterOptions{}, false
	}
}

// Common distro binaries use numeric suffixes, e.g. python3.12 and php8.3.
// Prefix lookalikes such as python-helper are deliberately excluded.
func versionedInterpreter(name, interpreter string) bool {
	if name == interpreter {
		return true
	}
	if !strings.HasPrefix(name, interpreter) {
		return false
	}
	suffix := strings.TrimPrefix(name, interpreter)
	for _, part := range strings.Split(suffix, ".") {
		if part == "" {
			return false
		}
		for _, char := range part {
			if char < '0' || char > '9' {
				return false
			}
		}
	}
	return true
}

func stringIn(value string, choices []string) bool {
	for _, choice := range choices {
		if value == choice {
			return true
		}
	}
	return false
}
