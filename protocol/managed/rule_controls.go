package managed

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	RuleWebDescendantRootShell           = "web-descendant-root-shell"
	RuleWebDescendantShell               = "web-descendant-shell"
	RuleWebDescendantDownloadTool        = "web-descendant-download-tool"
	RuleWebDescendantReconTool           = "web-descendant-recon-tool"
	RuleWebDescendantConnectionTool      = "web-descendant-connection-tool"
	RuleWebDescendantInlineInterpreter   = "web-descendant-inline-interpreter"
	RuleWebDescendantTemporaryExecutable = "web-descendant-temporary-executable"
	RuleWebDescendantTemporaryScript     = "web-descendant-temporary-script"
	RulePrivilegeRootExecution           = "privilege-root-execution"
	RulePrivilegeRootRestored            = "privilege-root-restored"
	RulePrivilegeHostRootGain            = "privilege-host-root-gain"
	RulePrivilegeRootIdentityChange      = "privilege-root-identity-change"
	RulePrivilegeCapabilityGain          = "privilege-capability-gain"
	RulePrivilegeCapabilityActivated     = "privilege-capability-activated"
	RuleServiceProtectedFileWrite        = "service-protected-file-write"
	RuleServiceUnexpectedTCPDestination  = "service-unexpected-tcp-destination"
)

var builtinRuleIDs = [...]string{
	RuleWebDescendantRootShell,
	RuleWebDescendantShell,
	RuleWebDescendantDownloadTool,
	RuleWebDescendantReconTool,
	RuleWebDescendantConnectionTool,
	RuleWebDescendantInlineInterpreter,
	RuleWebDescendantTemporaryExecutable,
	RuleWebDescendantTemporaryScript,
	RulePrivilegeRootExecution,
	RulePrivilegeRootRestored,
	RulePrivilegeHostRootGain,
	RulePrivilegeRootIdentityChange,
	RulePrivilegeCapabilityGain,
	RulePrivilegeCapabilityActivated,
	RuleServiceProtectedFileWrite,
	RuleServiceUnexpectedTCPDestination,
}

// BuiltinRuleIDs returns the rule identifiers accepted in signed controls.
func BuiltinRuleIDs() []string { return slices.Clone(builtinRuleIDs[:]) }

type ServiceRuleControl struct {
	Service   string     `json:"service" yaml:"service"`
	RuleID    string     `json:"rule_id" yaml:"rule_id"`
	Mode      string     `json:"mode" yaml:"mode"`
	Reason    string     `json:"reason,omitempty" yaml:"reason,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty" yaml:"expires_at,omitempty"`
}

func (c ServiceRuleControl) Allows(at time.Time) bool {
	switch c.Mode {
	case "enabled":
		return true
	case "suppress_until":
		return c.ExpiresAt != nil && !at.Before(*c.ExpiresAt)
	default:
		return false
	}
}

func ValidateServiceRuleControls(controls []ServiceRuleControl) error {
	if len(controls) > 256 {
		return errors.New("too many service rule controls")
	}
	seen := make(map[[2]string]bool, len(controls))
	for _, c := range controls {
		key := [2]string{c.Service, c.RuleID}
		if !validName(c.Service, false) || strings.EqualFold(c.Service, "unknown") || !slices.Contains(builtinRuleIDs[:], c.RuleID) || seen[key] {
			return errors.New("service rule controls require a distinct service and built-in rule ID")
		}
		seen[key] = true
		switch c.Mode {
		case "enabled", "disabled":
			if c.Reason != "" || c.ExpiresAt != nil {
				return errors.New("only a temporary service rule exception has a reason and expiry")
			}
		case "suppress_until":
			if c.ExpiresAt == nil || c.ExpiresAt.IsZero() || c.ExpiresAt.Year() < 1 || c.ExpiresAt.Year() > 9999 || c.Reason == "" || len(c.Reason) > 512 || strings.TrimSpace(c.Reason) != c.Reason || !utf8.ValidString(c.Reason) || strings.ContainsFunc(c.Reason, unicode.IsControl) {
				return errors.New("temporary service rule exception needs a bounded reason and UTC expiry")
			}
			if _, offset := c.ExpiresAt.Zone(); offset != 0 {
				return errors.New("service rule expiry must use UTC")
			}
		default:
			return fmt.Errorf("unsupported service rule mode for %s", c.RuleID)
		}
	}
	return nil
}
