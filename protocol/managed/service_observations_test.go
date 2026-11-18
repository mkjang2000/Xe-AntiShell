package managed

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"
)

func sampleServiceScope() ServiceObservationPolicy {
	return ServiceObservationPolicy{
		Service: "shop.service", ProtectedDirs: []string{"/srv/shop"}, AllowedWriteDirs: []string{"/srv/shop/uploads"},
		AllowedTCPDestinations: []TCPDestination{{CIDR: netip.MustParsePrefix("2001:db8::/32")}, {CIDR: netip.MustParsePrefix("192.0.2.0/24"), Ports: []uint16{443}}},
	}
}

func TestSignedServiceObservationScopes(t *testing.T) {
	now := time.Now().UTC()
	trusted, private := testSigningKeys(t)
	empty := []ServiceObservationPolicy{}
	configured := []ServiceObservationPolicy{sampleServiceScope()}
	var signatures []string
	for _, tc := range []struct {
		name    string
		scopes  *[]ServiceObservationPolicy
		content string
	}{
		{"inherit", nil, ""}, {"disable", &empty, `"service_observations":[]`}, {"replace", &configured, `"service_observations":[{`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := DefaultPolicy("agent", "enroll", 1, now)
			p.Detection.ServiceObservations = tc.scopes
			signed, err := SignPolicy(p, "current", private)
			if err != nil {
				t.Fatal(err)
			}
			wire, err := json.Marshal(signed)
			if err != nil {
				t.Fatal(err)
			}
			if tc.scopes == nil && bytes.Contains(wire, []byte("service_observations")) || !bytes.Contains(wire, []byte(tc.content)) {
				t.Fatalf("unexpected wire scope in %s", wire)
			}
			decoded, err := DecodeSignedPolicy(wire)
			if err != nil {
				t.Fatal(err)
			}
			verified, err := VerifyPolicy(decoded, trusted, "agent", "enroll", 1, now)
			if err != nil || !reflect.DeepEqual(tc.scopes, verified.Detection.ServiceObservations) {
				t.Fatalf("scope round trip: %v %v", verified.Detection.ServiceObservations, err)
			}
			for _, signature := range signatures {
				decoded.Signature = signature
				if _, err := VerifyPolicy(decoded, trusted, "agent", "enroll", 1, now); err == nil {
					t.Fatal("scope replacement kept the old signature valid")
				}
			}
			signatures = append(signatures, signed.Signature)
		})
	}
}

func TestServiceObservationPolicyValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*ServiceObservationPolicy)
	}{
		{"service syntax", func(s *ServiceObservationPolicy) { s.Service = "shop/worker" }},
		{"unattributed service", func(s *ServiceObservationPolicy) { s.Service = "unknown" }},
		{"unrepresentable signed service", func(s *ServiceObservationPolicy) { s.Service = strings.Repeat("a", 256) }},
		{"empty scope", func(s *ServiceObservationPolicy) { s.ProtectedDirs = nil; s.AllowedTCPDestinations = nil }},
		{"unclean path", func(s *ServiceObservationPolicy) { s.ProtectedDirs[0] = "/srv/../shop" }},
		{"oversize path", func(s *ServiceObservationPolicy) { s.ProtectedDirs[0] = "/" + strings.Repeat("a", 4096) }},
		{"control character", func(s *ServiceObservationPolicy) { s.ProtectedDirs[0] = "/srv/\nshop" }},
		{"duplicate path", func(s *ServiceObservationPolicy) { s.ProtectedDirs = append(s.ProtectedDirs, s.ProtectedDirs[0]) }},
		{"path count", func(s *ServiceObservationPolicy) { s.ProtectedDirs = make([]string, 33) }},
		{"exception outside root", func(s *ServiceObservationPolicy) { s.AllowedWriteDirs[0] = "/srv/shopping" }},
		{"destination count", func(s *ServiceObservationPolicy) { s.AllowedTCPDestinations = make([]TCPDestination, 33) }},
		{"host bits", func(s *ServiceObservationPolicy) {
			s.AllowedTCPDestinations[0].CIDR = netip.MustParsePrefix("192.0.2.1/24")
		}},
		{"mapped network", func(s *ServiceObservationPolicy) {
			s.AllowedTCPDestinations[0].CIDR = netip.MustParsePrefix("::ffff:192.0.2.0/120")
		}},
		{"missing CIDR", func(s *ServiceObservationPolicy) { s.AllowedTCPDestinations[0].CIDR = netip.Prefix{} }},
		{"port range", func(s *ServiceObservationPolicy) { s.AllowedTCPDestinations[0].Ports = []uint16{0} }},
		{"duplicate port", func(s *ServiceObservationPolicy) { s.AllowedTCPDestinations[0].Ports = []uint16{80, 80} }},
		{"port count", func(s *ServiceObservationPolicy) { s.AllowedTCPDestinations[0].Ports = make([]uint16, 65) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := sampleServiceScope()
			tc.mutate(&s)
			p := DefaultPolicy("agent", "enroll", 1, time.Now().UTC())
			p.Detection.ServiceObservations = &[]ServiceObservationPolicy{s}
			if p.Validate() == nil {
				t.Fatal("invalid service scope accepted")
			}
		})
	}
	scope := sampleServiceScope()
	for _, scopes := range [][]ServiceObservationPolicy{nil, {scope, scope}, make([]ServiceObservationPolicy, 65)} {
		if err := validateSignedServiceObservations(&scopes); err == nil {
			t.Fatal("invalid scope list accepted")
		}
	}
}

func TestStrictServiceObservationJSON(t *testing.T) {
	legacy := readCompatibilityGolden(t, "policy-v1-legacy.json")
	for _, field := range []string{
		`"service_observations":null`, `"service_observations":{}`, `"service_observations":[],"service_observations":[]`,
		`"service_observations":[{"algorithm":"future"}]`, `"service_observations":[{"allowed_tcp_destinations":[{"cidr":"example.invalid"}]}]`,
		`"service_observations":[{"allowed_tcp_destinations":[{"cidr":"192.0.2.0/24","ports":[65536]}]}]`, `"future_option":true`,
	} {
		wire := bytes.Replace(legacy, []byte(`"detection":{`), []byte(`"detection":{`+field+`,`), 1)
		if _, err := DecodeSignedPolicy(wire); err == nil {
			t.Errorf("accepted invalid detection field %s", field)
		}
	}
}

func TestServiceObservationPolicyWireLimit(t *testing.T) {
	now := time.Now().UTC()
	p := DefaultPolicy("agent", "enroll", 1, now)
	scope := sampleServiceScope()
	scope.AllowedWriteDirs = nil
	scope.ProtectedDirs = nil
	// Tune the final path to put the signed envelope exactly at its inclusive limit.
	for i := 0; i < 17; i++ {
		scope.ProtectedDirs = append(scope.ProtectedDirs, fmt.Sprintf("/%02d%s", i, strings.Repeat("x", 3790)))
	}
	scope.ProtectedDirs = append(scope.ProtectedDirs, "/z")
	scopes := []ServiceObservationPolicy{scope}
	p.Detection.ServiceObservations = &scopes
	trusted, private := testSigningKeys(t)
	signed, err := SignPolicy(p, "current", private)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	last := len(scopes[0].ProtectedDirs) - 1
	scopes[0].ProtectedDirs[last] += strings.Repeat("z", MaxPolicyBytes-len(body))
	signed, err = SignPolicy(p, "current", private)
	if err != nil {
		t.Fatal(err)
	}
	body, err = json.Marshal(signed)
	if err != nil || len(body) != MaxPolicyBytes {
		t.Fatalf("wire boundary %d: %v", len(body), err)
	}
	decoded, err := DecodeSignedPolicy(body)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = VerifyPolicy(decoded, trusted, "agent", "enroll", 1, now); err != nil {
		t.Fatal(err)
	}
	scopes[0].ProtectedDirs[last] += "z"
	if _, err = SignPolicy(p, "current", private); err == nil {
		t.Fatal("issuer signed an unreadable envelope")
	}
	// Sign the typed payload directly to test a valid signature with oversized framing.
	signature, err := signValue("policy", "current", p, private, MaxPolicyBytes)
	if err != nil {
		t.Fatal(err)
	}
	over := SignedPolicy{Policy: p, KeyID: "current", Signature: signature}
	if _, err = VerifyPolicy(over, trusted, "agent", "enroll", 1, now); err == nil {
		t.Fatal("accepted oversized envelope")
	}
}
