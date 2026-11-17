package collector

import (
	"encoding/hex"
	"strconv"
	"strings"
	"unicode/utf8"
)

// This matches the largest configurable argv limit and bounds allocation even
// when a malformed EXECVE record supplies an enormous argc or argument index.
const maxAuditArguments = 65536

// auditArgv validates a whole EXECVE group. Linux may emit argc only in the
// first of several records. Fragmented aN_len/aN[index] arguments are unsupported
// and must not make later arguments shift into an apparently exact argv.
type auditArgv struct {
	count     int
	countSeen bool
	invalid   bool
	values    map[int]string
}

func (a *auditArgv) add(record auditRecord) {
	if record.fieldsInvalid {
		a.invalid = true
		return
	}
	for key, value := range record.fields {
		if key == "argc" {
			count, ok := auditArgumentNumber(value)
			if !ok || a.countSeen && count != a.count {
				a.invalid = true
			}
			a.count, a.countSeen = count, true
			continue
		}
		if !strings.HasPrefix(key, "a") {
			continue
		}
		index, ok := auditArgumentNumber(strings.TrimPrefix(key, "a"))
		if !ok || index >= maxAuditArguments {
			a.invalid = true
			continue
		}
		argument, ok := exactAuditArgument(value, !record.quoted[key])
		if !ok {
			a.invalid = true
			continue
		}
		if a.values == nil {
			a.values = make(map[int]string)
		}
		if _, duplicate := a.values[index]; duplicate {
			a.invalid = true
		}
		a.values[index] = argument
	}
}

// normalized retains an unambiguous a0 fallback for existing EXECVE-only
// observations. Incomplete vectors are omitted so holes never become flags or
// leak undecodable argument contents past normal privacy redaction.
func (a *auditArgv) normalized() ([]string, string, bool) {
	if a.invalid {
		return nil, "", false
	}
	first := a.values[0]
	if !a.countSeen || len(a.values) != a.count {
		return nil, first, false
	}
	for index := range a.values {
		if index >= a.count {
			return nil, first, false
		}
	}
	argv := make([]string, a.count)
	for index, value := range a.values {
		argv[index] = value
	}
	return argv, first, true
}

func auditArgumentNumber(value string) (int, bool) {
	if value == "" || len(value) > 1 && value[0] == '0' {
		return 0, false
	}
	for _, digit := range value {
		if digit < '0' || digit > '9' {
			return 0, false
		}
	}
	number, err := strconv.ParseUint(value, 10, 32)
	if err != nil || number > maxAuditArguments {
		return 0, false
	}
	return int(number), true
}

func exactAuditArgument(value string, encoded bool) (string, bool) {
	if encoded {
		if value == "" || len(value)%2 != 0 {
			return "", false
		}
		decoded, err := hex.DecodeString(value)
		if err != nil {
			return "", false
		}
		value = string(decoded)
	}
	if !utf8.ValidString(value) || strings.IndexByte(value, 0) >= 0 {
		return "", false
	}
	return value, true
}
