package procfs

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	inventoryProcEntryLimit = 4096
	inventoryTotalFDLimit   = 32768
	inventoryPIDFDLimit     = 1024
	inventoryReadBatch      = 64
)

type socketOwner struct {
	service   string
	seen      bool
	ambiguous bool
}

func (s *Snapshotter) listenerOwners(ctx context.Context, listeners []tcpListener) (map[uint64]socketOwner, bool) {
	owners := make(map[uint64]socketOwner)
	for _, listener := range listeners {
		if listener.inode != 0 {
			owners[listener.inode] = socketOwner{}
		}
	}
	if len(owners) == 0 {
		return owners, ctx.Err() == nil
	}
	netNamespace, err := os.Readlink(filepath.Join(s.root, "self", "ns", "net"))
	if err != nil || netNamespace == "" {
		return owners, false
	}
	complete := true
	remainingFDs := inventoryTotalFDLimit
	err = walkInventoryNames(ctx, s.root, inventoryProcEntryLimit, func(name string) bool {
		pid, err := strconv.Atoi(name)
		if err != nil || pid <= 0 || strconv.Itoa(pid) != name {
			return true
		}
		if remainingFDs == 0 {
			return false
		}
		if !inspectListenerProcess(ctx, filepath.Join(s.root, name), netNamespace, pid, owners, &remainingFDs) {
			complete = false
		}
		return true
	})
	return owners, complete && err == nil
}

func inspectListenerProcess(ctx context.Context, path, netNamespace string, pid int, owners map[uint64]socketOwner, remainingFDs *int) bool {
	var matches map[uint64]string
	complete := true
	fdPath := filepath.Join(path, "fd")
	err := walkInventoryNames(ctx, fdPath, min(*remainingFDs, inventoryPIDFDLimit), func(name string) bool {
		(*remainingFDs)--
		fd := filepath.Join(fdPath, name)
		inode, err := readSocketInode(fd)
		if _, wanted := owners[inode]; wanted && err == nil {
			if matches == nil {
				matches = make(map[uint64]string)
			}
			matches[inode] = fd
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			complete = false
		}
		return true
	})
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		complete = false
	}
	if len(matches) == 0 {
		return complete
	}
	// Resolve unit membership only for PIDs that hold a candidate listener.
	// Re-read each matching descriptor between process identity checks so a
	// closing descriptor or a recycled PID cannot keep a previous association.
	first, ownerErr := readListenerIdentity(path, pid)
	for inode, fd := range matches {
		present, err := readSocketInode(fd)
		if present != inode || err != nil {
			delete(matches, inode)
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				complete = false
			}
		}
	}
	last, identityErr := readListenerIdentity(path, pid)
	service := ""
	if ownerErr == nil && identityErr == nil && first == last && last.netNamespace == netNamespace && pid != 1 {
		service = last.service
	}
	for inode := range matches {
		owner := owners[inode]
		if owner.seen && owner.service != service {
			owner.ambiguous = true
		}
		owner.service, owner.seen = service, true
		owners[inode] = owner
	}
	return complete && ownerErr == nil && identityErr == nil && first == last
}

func readSocketInode(fd string) (uint64, error) {
	link, err := os.Readlink(fd)
	if err != nil {
		return 0, err
	}
	inode, found := strings.CutPrefix(link, "socket:[")
	if !found {
		return 0, nil
	}
	inode, found = strings.CutSuffix(inode, "]")
	if !found {
		return 0, nil
	}
	value, err := strconv.ParseUint(inode, 10, 64)
	return value, err
}

type listenerIdentity struct {
	startTicks   uint64
	netNamespace string
	service      string
}

func readListenerIdentity(path string, pid int) (listenerIdentity, error) {
	stat, err := os.ReadFile(filepath.Join(path, "stat"))
	if err != nil {
		return listenerIdentity{}, err
	}
	whenPID, _, ticks, err := parseProcessStat(string(stat))
	if err != nil || whenPID != pid {
		return listenerIdentity{}, errors.New("invalid listener process identity")
	}
	group, err := os.ReadFile(filepath.Join(path, "cgroup"))
	if err != nil {
		return listenerIdentity{}, err
	}
	netNamespace, err := os.Readlink(filepath.Join(path, "ns", "net"))
	if err != nil {
		return listenerIdentity{}, err
	}
	return listenerIdentity{startTicks: ticks, netNamespace: netNamespace, service: systemServiceUnit(string(group))}, nil
}

func walkInventoryNames(ctx context.Context, path string, remaining int, visit func(string) bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		names, err := file.Readdirnames(min(inventoryReadBatch, remaining+1))
		for _, name := range names {
			if remaining == 0 || !visit(name) {
				return errInventoryLimit
			}
			remaining--
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}
