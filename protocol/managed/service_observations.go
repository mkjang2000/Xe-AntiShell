package managed

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/mkjang2000/Xe-AntiShell/protocol/model"
)

// ServiceObservationPolicy is the scope for one service. The active detection policy
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

// ValidateServiceObservations checks both local and centrally issued scope lists.
func ValidateServiceObservations(scopes []ServiceObservationPolicy) error {
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

func validateSignedServiceObservations(scopes *[]ServiceObservationPolicy) error {
	if scopes == nil {
		return nil
	}
	if *scopes == nil {
		return errors.New("service_observations must be a JSON array")
	}
	if err := ValidateServiceObservations(*scopes); err != nil {
		return err
	}
	for _, scope := range *scopes {
		if !validName(scope.Service, false) {
			return errors.New("service_observations requires a valid signed service name")
		}
	}
	return nil
}

// The pointer distinguishes omission from an empty list. JSON null must not
// turn a malformed replacement into a request to inherit the host settings.
func (d *DetectionPolicy) UnmarshalJSON(data []byte) error {
	type policyFields DetectionPolicy
	var decoded struct {
		policyFields
		Scopes   optionalPolicyList[ServiceObservationPolicy] `json:"service_observations"`
		Controls optionalPolicyList[ServiceRuleControl]       `json:"service_rule_controls"`
	}
	if err := DecodeStrict(data, MaxPolicyBytes, &decoded); err != nil {
		return err
	}
	*d = DetectionPolicy(decoded.policyFields)
	d.ServiceObservations = decoded.Scopes.list
	if decoded.Controls.list != nil {
		d.ServiceRuleControls = *decoded.Controls.list
	}
	return nil
}

type optionalPolicyList[T any] struct {
	list *[]T
}

func (f *optionalPolicyList[T]) UnmarshalJSON(data []byte) error {
	if f.list != nil {
		return errors.New("duplicate detection policy list")
	}
	var list []T
	if err := DecodeStrict(data, MaxPolicyBytes, &list); err != nil {
		return err
	}
	if list == nil {
		return errors.New("detection policy list must be a JSON array")
	}
	f.list = &list
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
