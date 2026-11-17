package privileges

import (
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// EventArgumentsUsable accepts only the reviewed unfiltered JSON subscription.
// getevents can otherwise silently remove root executions, fixed policy events,
// or credential proof. The privacy exclusions remove no identity/proof fields.
// Unknown flags fail closed rather than inheriting future CLI filter semantics.
func EventArgumentsUsable(args []string) bool {
	if len(args) == 0 || len(args) > 64 {
		return false
	}
	command, output := false, false
	seen := map[string]bool{}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "getevents" {
			if command {
				return false
			}
			command = true
			continue
		}
		key, value, inline := strings.Cut(arg, "=")
		switch key {
		case "--server-address", "--timeout", "--retries", "--output", "-o", "--exclude-fields", "-F":
		default:
			return false
		}
		if !inline {
			i++
			if i >= len(args) {
				return false
			}
			value = args[i]
		}
		if value == "" || len(value) > 4096 || strings.ContainsAny(value, "\x00\r\n") {
			return false
		}
		canonical := key
		if key == "-o" {
			canonical = "--output"
		}
		if key == "-F" {
			canonical = "--exclude-fields"
		}
		if canonical != "--exclude-fields" && seen[canonical] {
			return false
		}
		seen[canonical] = true
		switch canonical {
		case "--server-address":
			path := strings.TrimPrefix(value, "unix://")
			if !strings.HasPrefix(value, "unix:///run/") || filepath.Clean(path) != path {
				return false
			}
		case "--timeout":
			timeout, err := time.ParseDuration(value)
			if err != nil || timeout <= 0 || timeout > time.Minute {
				return false
			}
		case "--retries":
			retries, err := strconv.Atoi(value)
			if err != nil || retries < 0 || retries > 10 || strconv.Itoa(retries) != value {
				return false
			}
		case "--output":
			if value != "json" {
				return false
			}
			output = true
		case "--exclude-fields":
			// pflag's StringSlice accepts CSV quoting. Exact plain tokens avoid any
			// divergent CSV/escaping interpretation; broad prefixes are never safe.
			for _, field := range strings.Split(value, ",") {
				switch field {
				case "process.arguments", "process.environment_variables", "parent.arguments", "parent.environment_variables", "ancestors.arguments", "ancestors.environment_variables":
				default:
					return false
				}
			}
		}
	}
	return command && output
}
