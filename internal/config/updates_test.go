package config

import (
	"strings"
	"testing"
)

func TestManagedUpdateBootstrapDefaultAndExplicitOptOut(t *testing.T) {
	cfg, err := Decode(strings.NewReader("version: 1\n"))
	if err != nil || !cfg.Updates.Enabled {
		t.Fatal("bootstrap RPM cannot preserve existing configuration defaults")
	}
	cfg, err = Decode(strings.NewReader("version: 1\nupdates:\n  enabled: false\n"))
	if err != nil || cfg.Updates.Enabled {
		t.Fatal("host opt-out was ignored")
	}
	if _, err := Decode(strings.NewReader("version: 1\nupdates:\n  command: /tmp/untrusted\n")); err == nil {
		t.Fatal("remote update executable override accepted")
	}
}
