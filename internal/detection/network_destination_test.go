package detection

import (
	"net/netip"
	"testing"
	"time"

	"xe-antishell/internal/config"
	"xe-antishell/internal/identity"
	"xe-antishell/internal/model"
)

func testTCPInitiation(address string, port uint16, v6 bool) model.Event {
	var result int64
	n := &model.NetworkObservation{
		Family: "ipv4", Function: "tcp_v4_connect", PolicyName: "xeas-network-connect-v1",
		Operation: "connect", Protocol: "tcp", DestinationAddress: address, DestinationPort: port,
		ReturnValue: &result, Outcome: "initiated",
	}
	if v6 {
		n.Family, n.Function = "ipv6", "tcp_v6_connect"
	}
	return model.Event{
		ID: "event-network", Type: "network.connect", Source: "tetragon", EventTime: time.Unix(100, 0).UTC(),
		Process: model.Process{Key: "web-worker", OriginService: "orders.service"},
		Network: n, RedactedFields: []string{"raw_json", "process.arguments"},
	}
}

func TestTCPDestinationComparesAddressAndPortAsOneEntry(t *testing.T) {
	allowed := []config.TCPDestination{
		{CIDR: netip.MustParsePrefix("192.0.2.0/24"), Ports: []uint16{443}},
		{CIDR: netip.MustParsePrefix("192.0.2.5/32"), Ports: []uint16{8443, 9443}},
		{CIDR: netip.MustParsePrefix("2001:db8:a::/48")},
	}
	for _, tc := range []struct {
		name, address string
		port          uint16
		v6, finding   bool
	}{
		{"normal API", "192.0.2.37", 443, false, false},
		{"second matching entry", "192.0.2.5", 8443, false, false},
		{"other address on special port", "192.0.2.6", 8443, false, true},
		{"outside configured prefixes", "198.51.100.1", 443, false, true},
		{"IPv6 any port", "2001:db8:a::1", 65535, true, false},
		{"IPv6 outside prefix", "2001:db8:b::1", 443, true, true},
		{"mapped IPv4", "::ffff:192.0.2.5", 8443, true, false},
		{"mapped IPv4 restricted port", "::ffff:192.0.2.6", 8443, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			event := testTCPInitiation(tc.address, tc.port, tc.v6)
			found := evaluateTCPDestination(event, allowed)
			if !tc.finding {
				if len(found) != 0 {
					t.Fatalf("allowed destination produced %d findings", len(found))
				}
				return
			}
			if len(found) != 1 {
				t.Fatalf("wanted one finding, got %d", len(found))
			}
			f := found[0]
			if f.RuleID != ruleServiceUnexpectedTCPDestination || !f.DetectionOnly || f.RiskScore != 55 ||
				f.OriginService != event.Process.OriginService || len(f.EvidenceEventIDs) != 1 || f.EvidenceEventIDs[0] != event.ID ||
				f.ID != identity.FindingID(f.RuleID, operationRuleVersion, event.ID) {
				t.Fatalf("wrong policy finding: %+v", f)
			}
		})
	}
}

func TestTCPDestinationRequiresTypedInitiationEvidenceAndExplicitPolicy(t *testing.T) {
	allowed := []config.TCPDestination{{CIDR: netip.MustParsePrefix("192.0.2.0/24")}}
	failed := int64(-111)
	for _, tc := range []struct {
		name   string
		change func(*model.Event)
	}{
		{"failed", func(e *model.Event) { e.Network.ReturnValue, e.Network.Outcome = &failed, "failed" }},
		{"missing return", func(e *model.Event) { e.Network.ReturnValue, e.Network.Outcome = nil, "unknown" }},
		{"contradictory result", func(e *model.Event) { e.Network.ReturnValue = &failed }},
		{"unexpected outcome", func(e *model.Event) { e.Network.Outcome = "established" }},
		{"no payload", func(e *model.Event) { e.Network = nil }},
		{"wrong type", func(e *model.Event) { e.Type = "process.exec" }},
		{"wrong source", func(e *model.Event) { e.Source = "replay" }},
		{"wrong policy", func(e *model.Event) { e.Network.PolicyName = "custom" }},
		{"wrong function", func(e *model.Event) { e.Network.Function = "tcp_v6_connect" }},
		{"wrong family", func(e *model.Event) { e.Network.Family = "ipv6" }},
		{"other protocol", func(e *model.Event) { e.Network.Protocol = "udp" }},
		{"other operation", func(e *model.Event) { e.Network.Operation = "listen" }},
		{"missing address", func(e *model.Event) { e.Network.DestinationAddress = "" }},
		{"invalid IP", func(e *model.Event) { e.Network.DestinationAddress = "proxy.example" }},
		{"missing port", func(e *model.Event) { e.Network.DestinationPort = 0 }},
		{"with zone", func(e *model.Event) {
			e.Network.Family, e.Network.Function, e.Network.DestinationAddress = "ipv6", "tcp_v6_connect", "fe80::1%eth0"
		}},
		{"redacted evidence", func(e *model.Event) { e.RedactedFields = []string{"network.destination_address"} }},
		{"partial return", func(e *model.Event) { e.TruncatedFields = []string{"network.return_value"} }},
		{"missing typed fields", func(e *model.Event) { e.MissingFields = []string{"network"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			event := testTCPInitiation("198.51.100.1", 443, false)
			tc.change(&event)
			if got := evaluateTCPDestination(event, allowed); len(got) != 0 {
				t.Fatal("unproven TCP initiation produced a finding")
			}
		})
	}
	if got := evaluateTCPDestination(testTCPInitiation("198.51.100.1", 443, false), nil); len(got) != 0 {
		t.Fatal("service without a destination policy produced a finding")
	}
}

func BenchmarkTCPDestinationAllowed(b *testing.B) {
	// Repeatedly cover the maximum configured list with a match in its last
	// entry. No finding allocation should be needed in the normal path.
	event := testTCPInitiation("192.0.2.37", 443, false)
	entries := make([]config.TCPDestination, 32)
	for index := range entries {
		ports := make([]uint16, 64)
		for i := range ports {
			ports[i] = uint16(1024 + index*len(ports) + i)
		}
		entries[index] = config.TCPDestination{CIDR: netip.MustParsePrefix("192.0.2.0/24"), Ports: ports}
	}
	entries[len(entries)-1].Ports[63] = 443
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if len(evaluateTCPDestination(event, entries)) != 0 {
			b.Fatal("expected an allowed destination")
		}
	}
}
