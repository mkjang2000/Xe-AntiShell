package detection

import (
	"net/netip"
	"slices"

	"xe-antishell/internal/config"
	"xe-antishell/internal/model"
)

// The caller selects the allowlist for the service attributed to this event.
// A zero connect return at these hooks establishes initiation only.
func evaluateTCPDestination(event model.Event, allowed []config.TCPDestination) []model.Finding {
	n := event.Network
	if len(allowed) == 0 || event.Type != "network.connect" || event.Source != "tetragon" || n == nil ||
		n.PolicyName != "xeas-network-connect-v1" || n.Operation != "connect" || n.Protocol != "tcp" ||
		n.Outcome != "initiated" || n.ReturnValue == nil || *n.ReturnValue != 0 || n.DestinationPort == 0 {
		return nil
	}

	address, err := netip.ParseAddr(n.DestinationAddress)
	if err != nil || address.Zone() != "" {
		return nil
	}
	v4 := address.Is4() && n.Family == "ipv4" && n.Function == "tcp_v4_connect"
	v6 := address.Is6() && n.Family == "ipv6" && n.Function == "tcp_v6_connect"
	if !v4 && !v6 {
		return nil
	}
	// Dual-stack sockets can report IPv4 peers as ::ffff:a.b.c.d. Match
	// those peers against the same IPv4 policy as a native IPv4 socket.
	address = address.Unmap()

	for _, destination := range allowed {
		if destination.CIDR.Contains(address) && (len(destination.Ports) == 0 || slices.Contains(destination.Ports, n.DestinationPort)) {
			return nil
		}
	}
	if !evidenceFieldAvailable(event, "network") {
		return nil
	}
	return operationFinding(event, ruleServiceUnexpectedTCPDestination,
		"서비스의 허용 범위를 벗어난 목적지로 TCP 연결 시작을 관측했습니다.",
		"tcp_destination_outside_allowlist", 55)
}
