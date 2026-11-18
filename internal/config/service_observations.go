package config

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"xe-antishell/internal/model"
)

// ServiceObservationPolicy is a host-local scope. The active detection policy
// must also explicitly name this service before an operation is eligible.
type ServiceObservationPolicy struct {
	Service                string           `json:"service" yaml:"service"`
	ProtectedDirs          []string         `json:"protected_dirs,omitempty" yaml:"protected_dirs,omitempty"`
	AllowedWriteDirs       []string         `json:"allowed_write_dirs,omitempty" yaml:"allowed_write_dirs,omitempty"`
	AllowedTCPDestinations []TCPDestination `json:"allowed_tcp_destinations,omitempty" yaml:"allowed_tcp_destinations,omitempty"`
}

type TCPDestination struct {
	CIDR  netip.Prefix `json:"cidr" yaml:"cidr"`
	Ports []uint16     `json:"ports,omitempty" yaml:"ports,omitempty"`
}

func validateServiceObservations(scopes []ServiceObservationPolicy) error {
	if len(scopes) > 64 {
		return fmt.Errorf("service_observations accepts at most 64 services")
	}
	seen := make(map[string]bool, len(scopes))
	for _, scope := range scopes {
		name := scope.Service
		if name == "" || strings.EqualFold(name, "unknown") || strings.Contains(name, "/") || strings.TrimSpace(name) != name || len(name) > 512 || !utf8.ValidString(name) || strings.ContainsFunc(name, unicode.IsControl) || seen[name] {
			return fmt.Errorf("service_observations requires distinct, valid service names")
		}
		seen[name] = true
		if err := scope.validate(); err != nil {
			return fmt.Errorf("service_observations %q: %w", name, err)
		}
	}
	return nil
}

func (p ServiceObservationPolicy) validate() error {
	if len(p.ProtectedDirs) == 0 && len(p.AllowedTCPDestinations) == 0 {
		return fmt.Errorf("configure protected_dirs or allowed_tcp_destinations")
	}
	for _, dirs := range [][]string{p.ProtectedDirs, p.AllowedWriteDirs} {
		if len(dirs) > 32 {
			return fmt.Errorf("each directory list accepts at most 32 entries")
		}
		for i, dir := range dirs {
			if !model.CleanObservationPath(dir) || slices.Contains(dirs[:i], dir) {
				return fmt.Errorf("directory paths must be distinct clean absolute Linux paths")
			}
		}
	}
	for _, allowed := range p.AllowedWriteDirs {
		if !slices.ContainsFunc(p.ProtectedDirs, func(root string) bool { return model.WithinObservationDirectory(allowed, root) }) {
			return fmt.Errorf("allowed_write_dirs must be within a protected directory")
		}
	}
	if len(p.AllowedTCPDestinations) > 32 {
		return fmt.Errorf("allowed_tcp_destinations accepts at most 32 entries")
	}
	for _, dst := range p.AllowedTCPDestinations {
		if !dst.CIDR.IsValid() || dst.CIDR != dst.CIDR.Masked() || dst.CIDR.Addr().Is4In6() {
			return fmt.Errorf("cidr must be an IPv4 or IPv6 network prefix with no host bits or mapped address")
		}
		if len(dst.Ports) > 64 {
			return fmt.Errorf("each destination accepts at most 64 ports")
		}
		for i, port := range dst.Ports {
			if port == 0 || slices.Contains(dst.Ports[:i], port) {
				return fmt.Errorf("ports must be unique integers between 1 and 65535")
			}
		}
	}
	return nil
}
