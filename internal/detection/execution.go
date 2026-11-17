package detection

import (
	"path/filepath"
	"strings"
	"unicode/utf8"

	"xe-antishell/internal/model"
)

// SummarizeExecution extracts bounded invocation facts before argv or raw
// payloads can enter the queue. Known runtimes lose all arguments even when an
// unsupported option prevents classification, so code cannot leak through an
// unrecognized invocation. Repeated calls preserve already extracted facts.
func SummarizeExecution(event *model.Event) {
	if event == nil {
		return
	}
	runtime := interpreterRuntime(filepath.Base(event.Process.Exe))
	if event.Type == "process.exec" && event.Execution == nil {
		event.Execution = exactExecution(*event)
	}
	knownRuntime := runtime != "" || event.Execution != nil && interpreterRuntime(event.Execution.Runtime) != ""
	removedAncestor := false
	for index := range event.Ancestors {
		if len(event.Ancestors[index].Argv) != 0 {
			event.Ancestors[index].Argv = nil
			removedAncestor = true
		}
	}
	if removedAncestor {
		redactExecutionField(event, "ancestors.argv")
	}
	if knownRuntime && len(event.Process.Argv) != 0 {
		event.Process.Argv = nil
		redactExecutionField(event, "process.argv")
	}
	if knownRuntime && len(event.RawJSON) != 0 {
		event.RawJSON = nil
		redactExecutionField(event, "raw_json")
	}
}

func redactExecutionField(event *model.Event, field string) {
	for _, existing := range event.RedactedFields {
		if existing == field {
			return
		}
	}
	event.RedactedFields = append(event.RedactedFields, field)
}

// ValidExecutionEvidence validates an explicit, code-free invocation fact.
// It does not infer a new fact from argv or establish source authentication.
func ValidExecutionEvidence(event model.Event) bool {
	return event.Execution != nil && executionEvidence(event) != nil
}

func executionEvidence(event model.Event) *model.ExecutionObservation {
	if !fieldAvailable(event, "process.exe") {
		return nil
	}
	if event.Execution == nil {
		if event.Type == "process.exec" {
			return exactExecution(event)
		}
		return nil
	}
	observation := event.Execution
	options, supported := interpreterOptionSet(observation.Runtime)
	if !supported {
		return nil
	}
	if observation.Evidence == "tetragon_policy" {
		if event.Type != "process.exec_observation" || event.Source != "tetragon" || observation.Mode != "inline" || observation.ScriptLocation != "" || !stringIn(observation.Option, options.inlineFlags) {
			return nil
		}
		if runtime, option, ok := executionPolicy(observation.PolicyName); ok && runtime == observation.Runtime && option == observation.Option {
			return observation
		}
		return nil
	}
	if observation.Evidence != "exact_argv" || event.Type != "process.exec" || strings.EqualFold(event.Source, "tetragon") || observation.PolicyName != "" || !filepath.IsAbs(event.Process.Exe) || interpreterRuntime(filepath.Base(event.Process.Exe)) != observation.Runtime || !fieldAvailable(event, "audit.records") || !fieldAvailable(event, "audit.EOE") {
		return nil
	}
	// Whole-argv privacy removal follows extraction. Missing or truncated
	// source arguments cannot establish an exact proof in the first place.
	quality := event
	quality.RedactedFields = nil
	if !fieldAvailable(quality, "process.argv") {
		return nil
	}
	for _, field := range event.RedactedFields {
		if field == "process.argv_exact" || strings.HasPrefix(field, "process.argv.") || strings.HasPrefix(field, "process.argv[") {
			return nil
		}
	}
	if observation.Mode == "inline" && observation.ScriptLocation == "" && stringIn(observation.Option, options.inlineFlags) {
		return observation
	}
	if observation.Mode == "script" && (observation.Option == "" || stringIn(observation.Option, options.scriptFlags)) && stringIn(observation.ScriptLocation, []string{"temporary", "memory", "fd"}) {
		return observation
	}
	return nil
}

func executionPolicy(name string) (string, string, bool) {
	for _, policy := range []struct{ name, runtime, option string }{
		{"python-c", "python", "-c"}, {"node-e", "node", "-e"}, {"node-eval", "node", "--eval"},
		{"node-p", "node", "-p"}, {"node-print", "node", "--print"}, {"php-r", "php", "-r"},
		{"perl-e", "perl", "-e"}, {"perl-capital-e", "perl", "-E"}, {"ruby-e", "ruby", "-e"},
	} {
		if name == "xeas-exec-"+policy.name+"-v1" {
			return policy.runtime, policy.option, true
		}
	}
	return "", "", false
}

type interpreterOptions struct {
	inlineFlags, scriptFlags, switches, valuedFlags, joinedValues []string
}

// Only explicit options before the first script/module boundary qualify.
// Tetragon's flattened arguments are never treated as an argument vector.
func exactExecution(event model.Event) *model.ExecutionObservation {
	if strings.EqualFold(event.Source, "tetragon") || !filepath.IsAbs(event.Process.Exe) || !fieldAvailable(event, "process.exe") || !fieldAvailable(event, "process.argv") || len(event.Process.Argv) < 2 || !fieldAvailable(event, "audit.records") || !fieldAvailable(event, "audit.EOE") {
		return nil
	}
	for _, argument := range event.Process.Argv {
		if !utf8.ValidString(argument) || strings.IndexByte(argument, 0) >= 0 {
			return nil
		}
	}
	runtime := interpreterRuntime(filepath.Base(event.Process.Exe))
	options, supported := interpreterOptionSet(runtime)
	if !supported {
		return nil
	}
	args := event.Process.Argv[1:]
	for index := 0; index < len(args); index++ {
		argument := args[index]
		if stringIn(argument, options.inlineFlags) {
			if index+1 < len(args) && strings.TrimSpace(args[index+1]) != "" {
				return &model.ExecutionObservation{Runtime: runtime, Mode: "inline", Evidence: "exact_argv", Option: argument}
			}
			return nil
		}
		if stringIn(argument, options.scriptFlags) || argument == "--" {
			if index+1 >= len(args) {
				return nil
			}
			option := argument
			if option == "--" {
				option = ""
			}
			return scriptExecution(event, runtime, option, args[index+1])
		}
		if stringIn(argument, options.switches) {
			continue
		}
		if stringIn(argument, options.valuedFlags) {
			if index+1 >= len(args) {
				return nil
			}
			index++
			continue
		}
		joined := false
		for _, prefix := range options.joinedValues {
			if strings.HasPrefix(argument, prefix) && len(argument) > len(prefix) {
				joined = true
				break
			}
		}
		if joined {
			continue
		}
		if argument == "" || strings.HasPrefix(argument, "-") {
			return nil
		}
		return scriptExecution(event, runtime, "", argument)
	}
	return nil
}

func scriptExecution(event model.Event, runtime, option, script string) *model.ExecutionObservation {
	if script == "" || script == "-" || strings.IndexByte(script, 0) >= 0 {
		return nil
	}
	if !filepath.IsAbs(script) {
		if !fieldAvailable(event, "process.cwd") || !filepath.IsAbs(event.Process.CWD) {
			return nil
		}
		script = filepath.Join(event.Process.CWD, script)
	}
	script = filepath.Clean(script)
	location := ""
	switch {
	case strings.HasPrefix(script, "/memfd:") && len(script) > len("/memfd:"):
		location = "memory"
	case descriptorScriptPath(script):
		location = "fd"
	case temporaryPath(script, false):
		location = "temporary"
	}
	if location == "" {
		return nil
	}
	return &model.ExecutionObservation{Runtime: runtime, Mode: "script", Evidence: "exact_argv", Option: option, ScriptLocation: location}
}

func descriptorScriptPath(value string) bool {
	for _, prefix := range []string{"/dev/fd/", "/proc/self/fd/", "/proc/thread-self/fd/"} {
		if !strings.HasPrefix(value, prefix) {
			continue
		}
		name := strings.TrimPrefix(value, prefix)
		return name != "" && strings.Trim(name, "0123456789") == ""
	}
	return false
}

func interpreterRuntime(name string) string {
	for _, runtime := range []string{"python", "node", "php", "perl", "ruby"} {
		if versionedInterpreter(name, runtime) || runtime == "node" && versionedInterpreter(name, "nodejs") {
			return runtime
		}
	}
	return ""
}

func interpreterOptionSet(runtime string) (interpreterOptions, bool) {
	switch runtime {
	case "python":
		return interpreterOptions{inlineFlags: []string{"-c"}, switches: []string{"-B", "-E", "-I", "-O", "-OO", "-P", "-q", "-s", "-S", "-u", "-v", "-x", "-b", "-bb", "-d"}, valuedFlags: []string{"-W", "-X", "--check-hash-based-pycs"}, joinedValues: []string{"-W", "-X"}}, true
	case "node":
		return interpreterOptions{inlineFlags: []string{"-e", "--eval", "-p", "--print"}, switches: []string{"--no-warnings", "--trace-warnings", "--use-strict"}, valuedFlags: []string{"-r", "--require", "--loader", "--import", "--input-type"}, joinedValues: []string{"-r", "--require=", "--loader=", "--import=", "--input-type="}}, true
	case "perl":
		return interpreterOptions{inlineFlags: []string{"-e", "-E"}, switches: []string{"-w", "-W", "-T", "-t", "-s", "-n", "-p", "-l", "-a"}, valuedFlags: []string{"-M", "-m", "-I", "-F"}, joinedValues: []string{"-M", "-m", "-I", "-F"}}, true
	case "php":
		return interpreterOptions{inlineFlags: []string{"-r"}, scriptFlags: []string{"-f"}, switches: []string{"-n", "-q", "-C"}, valuedFlags: []string{"-d", "-c"}, joinedValues: []string{"-d", "-c"}}, true
	case "ruby":
		return interpreterOptions{inlineFlags: []string{"-e"}, switches: []string{"-w", "-W0", "-W1", "-W2", "-d", "-v", "-n", "-p", "-a", "-l", "-s", "--disable-gems"}, valuedFlags: []string{"-I", "-r", "-E", "--encoding"}, joinedValues: []string{"-I", "-r", "-E", "--encoding="}}, true
	default:
		return interpreterOptions{}, false
	}
}

// Numeric distro suffixes qualify; names such as python-helper do not.
func versionedInterpreter(name, interpreter string) bool {
	if name == interpreter {
		return true
	}
	if !strings.HasPrefix(name, interpreter) {
		return false
	}
	for _, part := range strings.Split(strings.TrimPrefix(name, interpreter), ".") {
		if part == "" || strings.Trim(part, "0123456789") != "" {
			return false
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
