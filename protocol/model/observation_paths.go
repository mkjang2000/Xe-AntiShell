package model

import (
	"path"
	"strings"
	"unicode"
	"unicode/utf8"
)

// CleanObservationPath accepts complete, absolute Linux paths as recorded.
func CleanObservationPath(value string) bool {
	return len(value) <= 4096 && path.IsAbs(value) && path.Clean(value) == value &&
		utf8.ValidString(value) && strings.IndexFunc(value, unicode.IsControl) < 0
}

// WithinObservationDirectory compares validated paths lexically, at a component
// boundary. It works for "/" and never resolves paths on the current host.
func WithinObservationDirectory(value, dir string) bool {
	if dir == "" || !strings.HasPrefix(value, dir) {
		return false
	}
	return len(value) == len(dir) || dir == "/" || value[len(dir)] == '/'
}
