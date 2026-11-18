package detection

import "testing"

func TestCatalogPolicyEligibilityAndVersions(t *testing.T) {
	for _, test := range []struct {
		name                      string
		options                   Options
		enabled                   bool
		base, extended, privilege int
	}{
		{"disabled", Options{WebServices: []string{"php"}, Shells: []string{"sh"}, ExtendedProcessRules: true, PrivilegeRules: true}, false, 0, 0, 0},
		{"base", Options{WebExecutables: []string{"nginx"}, Shells: []string{"bash"}}, true, 2, 0, 0},
		{"all", Options{WebServices: []string{"php"}, Shells: []string{"sh"}, ExtendedProcessRules: true, PrivilegeRules: true}, true, 2, 6, 6},
		{"no web origin", Options{Shells: []string{"sh"}, ExtendedProcessRules: true, PrivilegeRules: true}, true, 0, 0, 6},
		{"no shells", Options{WebServices: []string{"php"}, ExtendedProcessRules: true}, true, 0, 6, 0},
		{"excepted shell", Options{WebExecutables: []string{"nginx"}, Shells: []string{"sh"}, AllowedPairs: []string{"nginx:sh"}, ExtendedProcessRules: true}, true, 0, 6, 0},
		{"partially excepted shells", Options{WebExecutables: []string{"nginx"}, Shells: []string{"sh", "bash"}, AllowedPairs: []string{"nginx:sh"}}, true, 2, 0, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			seen := map[string]bool{}
			active := map[string]int{}
			for _, r := range NewWithOptions(test.options).Rules(test.enabled) {
				if seen[r.ID] || r.Title == "" || r.Description == "" || len(r.Sensors) == 0 || len(r.RequiredFields) == 0 || len(r.EventTypes) == 0 {
					t.Fatalf("incomplete or duplicate rule %+v", r)
				}
				seen[r.ID] = true
				if r.Enabled {
					active[r.Profile]++
				} else if r.Reason == "" {
					t.Fatalf("%s missing disabled reason", r.ID)
				}
				if r.Profile == "base" && test.options.ExtendedProcessRules && (r.Version != extendedRuleVersion || r.Response != "detection_only") {
					t.Fatalf("extended shell metadata %+v", r)
				}
			}
			if len(seen) != 16 || active["file"] != 0 || active["network"] != 0 || active["base"] != test.base || active["extended"] != test.extended || active["privilege"] != test.privilege {
				t.Fatalf("unique rules %d, enabled %+v", len(seen), active)
			}
		})
	}
}
