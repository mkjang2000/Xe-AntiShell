package collector

import (
	"encoding/json"
	"errors"
	"math/rand"
	"reflect"
	"strings"
	"testing"
	"unsafe"
)

func copyCapabilityStrings(values []string) []string {
	if values == nil {
		return nil
	}
	return append([]string{}, values...)
}

func compareCapabilityJSON(t testing.TB, raw []byte) {
	t.Helper()
	for _, initial := range [][]string{nil, {}, {"previous", "CAP_SETUID", "CAP_CHOWN"}} {
		for _, direct := range []bool{false, true} {
			standard := copyCapabilityStrings(initial)
			actual := tetragonCapabilityList(copyCapabilityStrings(initial))
			wantErr := json.Unmarshal(raw, &standard)
			var err error
			if direct {
				err = actual.UnmarshalJSON(raw)
			} else {
				err = json.Unmarshal(raw, &actual)
			}
			if (err == nil) != (wantErr == nil) || !reflect.DeepEqual([]string(actual), standard) {
				t.Fatalf("decode differs from []string: direct=%v raw=%q got=%#v err=%v want=%#v err=%v", direct, raw, actual, err, standard, wantErr)
			}
		}
	}
}

func TestCapabilityJSONDifferential(t *testing.T) {
	cases := []string{
		`null`, `[]`, ` [ ] `, "\t\r\n[\t\r\n\"CAP_SETUID\" , \"DAC_OVERRIDE\"\n]\r\n",
		`["CAP_SETUID"]`, `["CAP_SETUID","CAP_SETUID"]`, `["DAC_OVERRIDE","CAP_DAC_OVERRIDE"]`,
		`["CAP_FUTURE"]`, `[""]`, `["cap_setuid"]`, `["CAP_SETUID "]`, `["CAP_SETUID\\"]`,
		`["\u0043AP_SETUID"]`, `["CAP_\u0053ETUID"]`, `["CAP_\u0053ETUID","CAP_CHOWN"]`,
		`["\uD800"]`, `["\uDC00"]`, `["\uD83D\uDE00"]`, `["\u0000"]`,
		`["\"CAP_SETUID\""]`, `["\\"]`, `["\/"]`, `["\b\f\n\r\t"]`,
		`[null]`, `[null,"CAP_SETUID"]`, `["CAP_SETUID",null]`, `[0]`, `[1.5]`, `[true]`, `[{}]`, `[[]]`,
		`["CAP_SETUID",0,"CAP_CHOWN"]`, `0`, `1e99999`, `false`, `{}`, `"CAP_SETUID"`,
		``, ` `, `[`, `]`, `["CAP_SETUID"`, `["CAP_SETUID",]`, `[,"CAP_SETUID"]`,
		`["CAP_SETUID" "CAP_CHOWN"]`, `["CAP_SETUID"]null`, `["CAP_SETUID"][]`,
		"[\"CAP_SETUID\"]\v", "[\"CAP_SET\x00UID\"]", "[\"CAP_SET\xffUID\"]", "[\"CAP_é\"]",
	}
	for _, raw := range cases {
		compareCapabilityJSON(t, []byte(raw))
	}
	for _, value := range hotPathCaps() {
		raw, _ := json.Marshal([]string{value})
		compareCapabilityJSON(t, raw)
	}
	for length := 0; length <= 66; length++ {
		values := make([]string, length)
		for index := range values {
			values[index] = "CAP_SETUID"
		}
		raw, _ := json.Marshal(values)
		compareCapabilityJSON(t, raw)
	}
	// Exercise every ASCII byte both as escaped JSON data and as an unescaped
	// input byte. Invalid controls/quotes must fall back to standard rejection.
	for value := 0; value < 128; value++ {
		token := "CAP_" + string([]byte{byte(value)}) + "SETUID"
		raw, _ := json.Marshal([]string{token})
		compareCapabilityJSON(t, raw)
		compareCapabilityJSON(t, append(append([]byte(`["`), []byte(token)...), []byte(`"]`)...))
	}
	valid := []byte(` ["CAP_SETUID", "DAC_OVERRIDE", "CAP_CHOWN"] `)
	for end := range valid {
		compareCapabilityJSON(t, valid[:end])
	}
}

func TestCapabilityJSONProperty(t *testing.T) {
	random := rand.New(rand.NewSource(846192))
	choices := append(hotPathCaps(), "DAC_OVERRIDE", "CAP_FUTURE", "", "CAP_é", "CAP_\"SETUID", "CAP_\\SETUID")
	for sample := 0; sample < 2000; sample++ {
		values := make([]string, random.Intn(80))
		for index := range values {
			values[index] = choices[random.Intn(len(choices))]
		}
		raw, _ := json.Marshal(values)
		if sample%2 == 0 {
			raw = append(append([]byte("\n\t "), raw...), '\r')
		}
		compareCapabilityJSON(t, raw)
	}
}

func TestCapabilityJSONFastPathAndOwnership(t *testing.T) {
	for _, raw := range []string{`[]`, `["CAP_SETUID"]`, `["DAC_OVERRIDE"]`, `["CAP_SETUID","CAP_SETUID"]`,
		"\n [ \"CAP_SETUID\" , \"CAP_CHOWN\" ] \r", `[` + strings.Repeat(`"CAP_SETUID",`, 63) + `"CAP_SETUID"]`} {
		values, ok := knownTetragonCapabilityArray([]byte(raw))
		if !ok || values == nil || cap(values) != len(values) {
			t.Fatalf("known array did not produce exact owned slice: %q", raw)
		}
	}
	for _, raw := range []string{`null`, `["\u0043AP_SETUID"]`, `["CAP_FUTURE"]`, `[null]`, `[0]`, `true`, `["CAP_SETUID",]`,
		`[` + strings.Repeat(`"CAP_SETUID",`, 64) + `"CAP_SETUID"]`} {
		if _, ok := knownTetragonCapabilityArray([]byte(raw)); ok {
			t.Fatalf("non-canonical array took fast path: %q", raw)
		}
	}
	raw := []byte(`["CAP_SETUID","DAC_OVERRIDE"]`)
	previous := tetragonCapabilityList{"previous"}
	values := previous
	if err := values.UnmarshalJSON(raw); err != nil {
		t.Fatal(err)
	}
	sibling, _ := knownTetragonCapabilityArray(raw)
	for index := range raw {
		raw[index] = 0
	}
	if values[0] != "CAP_SETUID" || values[1] != "DAC_OVERRIDE" || previous[0] != "previous" {
		t.Fatal("decoded strings alias raw bytes or receiver storage")
	}
	if unsafe.StringData(values[0]) != unsafe.StringData(tetragonCapabilityNames["CAP_SETUID"]) ||
		unsafe.StringData(values[1]) != unsafe.StringData("DAC_OVERRIDE") {
		t.Fatal("known enum token was not interned to immutable source spelling")
	}
	values[0] = "changed"
	if sibling[0] != "CAP_SETUID" {
		t.Fatal("decoded arrays share mutable slice storage")
	}
}

func TestCapabilityJSONNormalizationAndFields(t *testing.T) {
	for _, raw := range []string{
		`{"effective":["DAC_OVERRIDE","CAP_SETUID"],"permitted":[],"inheritable":null}`,
		`{"effective":["CAP_SETUID","CAP_SETUID"]}`, `{"effective":["DAC_OVERRIDE","CAP_DAC_OVERRIDE"]}`,
		`{"effective":["CAP_FUTURE"]}`, `{"effective":[null]}`, `{"effective":["\u0043AP_SETUID"]}`,
		`{"effective":["CAP_SETUID"],"effective":null}`, `{"effective":null,"effective":[]}`,
	} {
		var source tetragonCapabilities
		if err := json.Unmarshal([]byte(raw), &source); err != nil {
			t.Fatal(err)
		}
		var standard struct {
			Effective   []string `json:"effective"`
			Permitted   []string `json:"permitted"`
			Inheritable []string `json:"inheritable"`
		}
		if err := json.Unmarshal([]byte(raw), &standard); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual([]string(source.Effective), standard.Effective) || !reflect.DeepEqual([]string(source.Permitted), standard.Permitted) || !reflect.DeepEqual([]string(source.Inheritable), standard.Inheritable) {
			t.Fatal("capability object changed field values or null/empty shape")
		}
		_, err := normalizedTetragonCapabilities(&source)
		rejected := strings.Contains(raw, `CAP_FUTURE`) || strings.Contains(raw, `[null]`) || strings.Contains(raw, `"CAP_SETUID","CAP_SETUID"`) || strings.Contains(raw, `"DAC_OVERRIDE","CAP_DAC_OVERRIDE"`)
		if errors.Is(err, ErrUnsupportedEvent) != rejected {
			t.Fatalf("normalizer support boundary changed: %q err=%v", raw, err)
		}
	}
}

func FuzzCapabilityJSONDifferential(f *testing.F) {
	for _, raw := range []string{`[]`, `null`, `["CAP_SETUID"]`, `["DAC_OVERRIDE"]`, `["CAP_FUTURE"]`, `[null]`, `["\u0043AP_SETUID"]`, `["CAP_SETUID",]`} {
		f.Add([]byte(raw))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 8192 {
			return
		}
		compareCapabilityJSON(t, raw)
	})
}

func BenchmarkCapabilityJSON(b *testing.B) {
	full, _ := json.Marshal(hotPathCaps())
	fixtures := []struct {
		name string
		raw  []byte
	}{
		{"full41", full}, {"small", []byte(`["CAP_SETUID","DAC_OVERRIDE"]`)}, {"empty", []byte(`[]`)},
		{"escaped_fallback", []byte(`["\u0043AP_SETUID"]`)}, {"unknown_fallback", []byte(`["CAP_FUTURE"]`)},
	}
	for _, fixture := range fixtures {
		b.Run(fixture.name, func(b *testing.B) {
			b.Run("standard", func(b *testing.B) {
				b.ReportAllocs()
				for index := 0; index < b.N; index++ {
					var values []string
					if err := json.Unmarshal(fixture.raw, &values); err != nil {
						b.Fatal(err)
					}
				}
			})
			b.Run("candidate", func(b *testing.B) {
				b.ReportAllocs()
				for index := 0; index < b.N; index++ {
					var values tetragonCapabilityList
					if err := json.Unmarshal(fixture.raw, &values); err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
}
