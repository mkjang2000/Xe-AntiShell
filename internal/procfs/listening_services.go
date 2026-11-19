package procfs

import (
	"bufio"
	"cmp"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"xe-antishell/internal/model"
)

const (
	tcpTableByteLimit = 4 << 20
	tcpTableRowLimit  = 32768
	tcpListenerLimit  = 256 // per address family, before grouping report rows
)

type tcpListener struct {
	model.ServiceListener
	inode uint64
}

var errInventoryLimit = errors.New("service inventory scan limit reached")

// ListeningServices observes TCP sockets in the agent's current network
// namespace. An empty Service means ownership could not be reduced to one
// directly verified systemd service. No bind addresses or PIDs leave procfs.
func (s *Snapshotter) ListeningServices(ctx context.Context) model.ServiceInventory {
	result := model.ServiceInventory{SampledAt: time.Now().UTC(), State: "unavailable", Listeners: []model.ServiceListener{}}
	if s == nil || !filepath.IsAbs(s.root) || ctx.Err() != nil {
		return result
	}
	result.SampledAt = s.now().UTC()
	var listeners []tcpListener
	var tablesRead int
	for _, family := range []struct {
		file string
		name string
		size int
	}{{"tcp", "ipv4", 4}, {"tcp6", "ipv6", 16}} {
		rows, complete, err := readTCPListeners(ctx, filepath.Join(s.root, "net", family.file), family.name, family.size)
		if err != nil {
			continue
		}
		listeners = append(listeners, rows...)
		if complete {
			tablesRead++
		}
		result.State = "partial"
	}
	if result.State == "unavailable" {
		return result
	}
	owners, ownersComplete := s.listenerOwners(ctx, listeners)
	if tablesRead == 2 && ownersComplete {
		result.State = "complete"
	}
	for _, socket := range listeners {
		if owner := owners[socket.inode]; !owner.ambiguous {
			socket.Service = owner.service
		}
		result.Listeners = append(result.Listeners, socket.ServiceListener)
	}
	slices.SortFunc(result.Listeners, compareServiceListener)
	result.Listeners = slices.Compact(result.Listeners)
	if len(result.Listeners) > model.MaxServiceInventoryListeners {
		result.Listeners = result.Listeners[:model.MaxServiceInventoryListeners]
		result.State = "partial"
	}
	return result
}

func compareServiceListener(a, b model.ServiceListener) int {
	serviceOrder := strings.Compare(a.Service, b.Service)
	if a.Service == "" || b.Service == "" {
		serviceOrder = -serviceOrder
	}
	return cmp.Or(serviceOrder, cmp.Compare(a.Port, b.Port),
		strings.Compare(a.Family, b.Family), strings.Compare(a.Binding, b.Binding))
}

func readTCPListeners(ctx context.Context, path, family string, addressBytes int) ([]tcpListener, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer file.Close()
	reader := &io.LimitedReader{R: file, N: tcpTableByteLimit + 1}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 4096), 4096)
	if !scanner.Scan() {
		return nil, false, errors.New("proc TCP table header is unavailable")
	}
	header := strings.Fields(scanner.Text())
	if len(header) < 4 || header[0] != "sl" || header[1] != "local_address" || header[3] != "st" {
		return nil, false, errors.New("invalid proc TCP table header")
	}
	var listeners []tcpListener
	complete := true
	for rows := 0; scanner.Scan(); rows++ {
		if rows >= tcpTableRowLimit || ctx.Err() != nil {
			return listeners, false, nil
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			complete = false
			continue
		}
		if fields[3] != "0A" {
			continue
		}
		if len(fields) < 10 {
			complete = false
			continue
		}
		listener, valid := parseTCPListener(fields[1], fields[9], family, addressBytes)
		if !valid {
			complete = false
			continue
		}
		if len(listeners) >= tcpListenerLimit {
			return listeners, false, nil
		}
		listeners = append(listeners, listener)
	}
	return listeners, complete && scanner.Err() == nil && reader.N > 0 && ctx.Err() == nil, nil
}

func parseTCPListener(local, inode, family string, addressBytes int) (tcpListener, bool) {
	address, portText, found := strings.Cut(local, ":")
	if !found || len(address) != addressBytes*2 || len(portText) != 4 {
		return tcpListener{}, false
	}
	var ip [16]byte
	if _, err := hex.Decode(ip[:addressBytes], []byte(address)); err != nil {
		return tcpListener{}, false
	}
	port, portErr := strconv.ParseUint(portText, 16, 16)
	socket, inodeErr := strconv.ParseUint(inode, 10, 64)
	if portErr != nil || inodeErr != nil || port == 0 {
		return tcpListener{}, false
	}
	// proc prints each 32-bit address word in host byte order.
	for i := 0; i < addressBytes; i += 4 {
		word := ip[i : i+4]
		binary.BigEndian.PutUint32(word, binary.NativeEndian.Uint32(word))
	}
	addr, _ := netip.AddrFromSlice(ip[:addressBytes])
	addr = addr.Unmap()
	binding := "interface"
	if addr.IsUnspecified() {
		binding = "wildcard"
	} else if addr.IsLoopback() {
		binding = "loopback"
	}
	return tcpListener{ServiceListener: model.ServiceListener{Port: uint16(port), Family: family, Binding: binding}, inode: socket}, true
}
