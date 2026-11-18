package config

import (
	"net/netip"
	"strings"
	"testing"
)

func TestServiceObservationsDecode(t *testing.T) {
	const policy = `service_observations:
  - service: shop.service
    protected_dirs: [/srv/shop]
    allowed_write_dirs: [/srv/shop/upload]
    allowed_tcp_destinations:
      - cidr: 192.0.2.0/24
        ports: [443, 8443]
      - cidr: 2001:db8::/32
`
	cfg, err := Decode(strings.NewReader(policy))
	if err != nil {
		t.Fatal(err)
	}
	dst := cfg.ServiceObservations[0].AllowedTCPDestinations
	if len(dst) != 2 || dst[0].CIDR != netip.MustParsePrefix("192.0.2.0/24") || dst[0].Ports[1] != 8443 || len(dst[1].Ports) != 0 {
		t.Fatalf("wrong allowed destinations %+v", dst)
	}
	for _, tc := range []struct{ from, to string }{
		{"shop.service", "unknown"},
		{"/srv/shop]", "/srv/../shop]"},
		{"/srv/shop/upload", "/srv/shopping/upload"},
		{"192.0.2.0/24", "local.example"},
		{"192.0.2.0/24", "192.0.2.7/24"},
		{"192.0.2.0/24", "::ffff:192.0.2.0/120"},
		{"443, 8443", "443, 0"},
		{"443, 8443", "443, 443"},
		{"443, 8443", "65536"},
		{"ports:", "port:"},
	} {
		if _, err := Decode(strings.NewReader(strings.Replace(policy, tc.from, tc.to, 1))); err == nil {
			t.Errorf("accepted %q in place of %q", tc.to, tc.from)
		}
	}
	if _, err := Decode(strings.NewReader(policy + "  - service: shop.service\n    protected_dirs: [/other]\n")); err == nil {
		t.Error("accepted duplicate service scope")
	}
}
