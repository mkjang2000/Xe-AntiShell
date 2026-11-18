package detection

import (
	"net/netip"
	"testing"
	"time"

	"xe-antishell/internal/config"
)

func TestServiceObservationSnapshotExactScopeAndEvidence(t *testing.T) {
	opts := Options{
		WebExecutables: []string{"alias.service"}, WebServices: []string{"Shop.service"},
		ServiceObservations: []config.ServiceObservationPolicy{
			{Service: "alias.service", ProtectedDirs: []string{"/srv"}},
			{Service: "Shop.service", ProtectedDirs: []string{"/srv"}, AllowedTCPDestinations: []config.TCPDestination{{CIDR: netip.MustParsePrefix("192.0.2.0/24"), Ports: []uint16{443}}}},
		},
	}
	engine := NewWithOptions(opts)
	opts.ServiceObservations[1].ProtectedDirs[0] = "/other"
	opts.ServiceObservations[1].AllowedTCPDestinations[0].Ports[0] = 22
	event := protectedWriteEvent()
	event.BootID, event.Process.PID, event.Process.ExecID = "boot", 20, "worker-id"
	event.Process.StartTime = time.Unix(100, 0)
	event.Process.OriginService = "Shop.service"
	event.File.Path = "/srv/index.php"
	if len(engine.Evaluate(event, nil)) != 1 {
		t.Fatal("lost explicitly scoped write or snapshot aliased caller's directories")
	}
	tcp := testTCPInitiation("192.0.2.3", 443, false)
	tcp.EventTime, tcp.BootID, tcp.Process = event.EventTime, event.BootID, event.Process
	if len(engine.Evaluate(tcp, nil)) != 0 {
		t.Fatal("mutating original ports changed active snapshot")
	}
	tcp.Network.DestinationPort = 22
	if len(engine.Evaluate(tcp, nil)) != 1 {
		t.Fatal("original port policy was not enforced")
	}
	for _, service := range []string{"alias.service", "shop.service", "", "unknown"} {
		event.Process.OriginService = service
		if len(engine.Evaluate(event, nil)) != 0 {
			t.Fatalf("used an alias or non-exact service %q", service)
		}
	}
	event.Process.OriginService = "Shop.service"
	event.MissingFields = []string{"process.origin_service"}
	if len(engine.Evaluate(event, nil)) != 0 {
		t.Fatal("accepted marked-missing attribution")
	}
}
