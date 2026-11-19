package procfs

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"xe-antishell/internal/model"
)

const tcpTableHeader = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
const inventoryTestNetNS = "net:[4026531993]"

func TestListeningServicesScopeAndOwnerEvidence(t *testing.T) {
	root := t.TempDir()
	writeTCPTable(t, root, "tcp",
		tcpRow("0.0.0.0", 443, "0A", 100),
		tcpRow("172.16.1.2", 8080, "0A", 101),
		tcpRow("127.251.0.1", 5432, "0A", 102),
		tcpRow("127.0.0.1", 46000, "01", 103),
		tcpRow("127.0.0.2", 5432, "0A", 104),
		tcpRow("127.0.0.1", 5480, "0A", 105),
		tcpRow("127.0.0.1", 8444, "0A", 106),
		tcpRow("127.0.0.1", 8445, "0A", 107),
	)
	writeTCPTable(t, root, "tcp6",
		tcpRow("::", 443, "0A", 108),
		tcpRow("::1", 80, "0A", 109),
		tcpRow("::ffff:127.0.0.3", 80, "0A", 110),
		tcpRow("2001:db8::9", 88, "0A", 111),
	)
	inventoryTestNamespace(t, root, "self", inventoryTestNetNS)
	writeListenerOwner(t, root, 10, "0::/system.slice/nginx.service", inventoryTestNetNS, 100, 101, 108)
	writeListenerOwner(t, root, 12, "0::/system.slice/nginx.service", inventoryTestNetNS, 100, 101, 108, 107)
	writeListenerOwner(t, root, 13, "0::/system.slice/system-db.slice/db.service", inventoryTestNetNS, 102, 104, 103, 107)
	writeListenerOwner(t, root, 14, "0::/user.slice/user-1000.slice/user@1000.service/app.slice/different.service", inventoryTestNetNS, 105, 106)
	writeListenerOwner(t, root, 15, "0::/system.slice/system-app.slice/different.service", "net:[4026532002]", 109)
	writeListenerOwner(t, root, 16, "0::/system.slice/docker.service/docker-deadbeef.scope/system.slice/nginx.service", inventoryTestNetNS, 111)
	writeListenerOwner(t, root, 1, "0::/init.scope", inventoryTestNetNS, 105, 110)

	s := New(root)
	now := time.Date(2026, 11, 19, 15, 0, 0, 0, time.FixedZone("KST", 9*60*60))
	s.now = func() time.Time { return now }
	actual := s.ListeningServices(context.Background())
	want := []model.ServiceListener{
		{Service: "db.service", Port: 5432, Family: "ipv4", Binding: "loopback"},
		{Service: "nginx.service", Port: 443, Family: "ipv4", Binding: "wildcard"},
		{Service: "nginx.service", Port: 443, Family: "ipv6", Binding: "wildcard"},
		{Service: "nginx.service", Port: 8080, Family: "ipv4", Binding: "interface"},
		{Port: 80, Family: "ipv6", Binding: "loopback"},
		{Port: 88, Family: "ipv6", Binding: "interface"},
		{Port: 5480, Family: "ipv4", Binding: "loopback"},
		{Port: 8444, Family: "ipv4", Binding: "loopback"},
		{Port: 8445, Family: "ipv4", Binding: "loopback"},
	}
	if actual.State != "complete" || actual.SampledAt != now.UTC() || !slices.Equal(actual.Listeners, want) {
		t.Fatalf("listening services = %#v, want %v", actual, want)
	}
}

func TestListeningServicesUnavailableEmptyAndPartial(t *testing.T) {
	root := t.TempDir()
	s := New(root)
	if out := s.ListeningServices(context.Background()); out.State != "unavailable" || len(out.Listeners) != 0 {
		t.Fatalf("missing tables: %+v", out)
	}
	writeTCPTable(t, root, "tcp")
	if out := s.ListeningServices(context.Background()); out.State != "partial" || len(out.Listeners) != 0 {
		t.Fatalf("one readable table: %+v", out)
	}
	writeTCPTable(t, root, "tcp6")
	if out := s.ListeningServices(context.Background()); out.State != "complete" || len(out.Listeners) != 0 {
		t.Fatalf("empty inventory: %+v", out)
	}
	writeTCPTable(t, root, "tcp", tcpRow("127.0.0.1", 443, "0A", 100))
	if out := s.ListeningServices(context.Background()); out.State != "partial" || len(out.Listeners) != 1 || out.Listeners[0].Service != "" {
		t.Fatalf("missing namespace attribution: %+v", out)
	}
	inventoryTestNamespace(t, root, "self", inventoryTestNetNS)
	writeTCPTable(t, root, "tcp", tcpRow("127.0.0.1", 443, "0A", 100), "0: malformed endpoint 0A")
	if out := s.ListeningServices(context.Background()); out.State != "partial" || len(out.Listeners) != 1 {
		t.Fatalf("malformed line: %+v", out)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if out := s.ListeningServices(ctx); out.State != "unavailable" || len(out.Listeners) != 0 {
		t.Fatalf("cancelled before collection: %+v", out)
	}
}

func TestListeningServicesCapsSortedOutputAndFileDescriptors(t *testing.T) {
	root := t.TempDir()
	lines := make([]string, 0, model.MaxServiceInventoryListeners+1)
	for i := model.MaxServiceInventoryListeners + 1; i >= 1; i-- {
		lines = append(lines, tcpRow("0.0.0.0", 1000+i, "0A", i))
	}
	writeTCPTable(t, root, "tcp", lines...)
	writeTCPTable(t, root, "tcp6")
	inventoryTestNamespace(t, root, "self", inventoryTestNetNS)
	s := New(root)
	out := s.ListeningServices(context.Background())
	if out.State != "partial" || len(out.Listeners) != model.MaxServiceInventoryListeners || out.Listeners[0].Port != 1001 || out.Listeners[len(out.Listeners)-1].Port != 1000+model.MaxServiceInventoryListeners {
		t.Fatalf("limited inventory = %+v", out)
	}
	writeListenerOwner(t, root, 10, "0::/system.slice/nginx.service", inventoryTestNetNS, 1, 2)
	out = s.ListeningServices(context.Background())
	if out.Listeners[0].Service != "nginx.service" || out.Listeners[0].Port != 1001 || out.Listeners[1].Service != "nginx.service" || out.Listeners[1].Port != 1002 {
		t.Fatalf("known owner was lost before the unknown rows: %+v", out)
	}
	visited := 0
	walk := walkInventoryNames(context.Background(), filepath.Join(root, "10", "fd"), 1, func(string) bool {
		visited++
		return true
	})
	if !errors.Is(walk, errInventoryLimit) || visited != 1 {
		t.Fatalf("bounded name walk visited %d: %v", visited, walk)
	}
}

func writeTCPTable(t *testing.T, root, name string, rows ...string) {
	t.Helper()
	dir := filepath.Join(root, "net")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	text := tcpTableHeader
	for _, row := range rows {
		text += "   " + row + "\n"
	}
	writeFixture(t, filepath.Join(dir, name), text)
}

func tcpRow(address string, port int, state string, inode int) string {
	addr := netip.MustParseAddr(address).AsSlice()
	var hex strings.Builder
	for i := 0; i < len(addr); i += 4 {
		fmt.Fprintf(&hex, "%08X", binary.NativeEndian.Uint32(addr[i:i+4]))
	}
	return fmt.Sprintf("0: %s:%04X 00000000:0000 %s 00000000:00000000 00:00000000 00000000 0 0 %d 1", hex.String(), port, state, inode)
}

func inventoryTestNamespace(t *testing.T, root, pid, netns string) {
	t.Helper()
	dir := filepath.Join(root, pid, "ns")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(netns, filepath.Join(dir, "net")); err != nil {
		t.Fatal(err)
	}
}

func writeListenerOwner(t *testing.T, root string, pid int, cgroup, netns string, sockets ...int) {
	t.Helper()
	writeProcessFixture(t, root, pid, 1, 100, "/fixture/exe", "0 0 0 0", "0 0 0 0", cgroup)
	inventoryTestNamespace(t, root, stringInt(pid), netns)
	dir := filepath.Join(root, stringInt(pid), "fd")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	for fd, socket := range sockets {
		if err := os.Symlink(fmt.Sprintf("socket:[%d]", socket), filepath.Join(dir, stringInt(fd))); err != nil {
			t.Fatal(err)
		}
	}
}
