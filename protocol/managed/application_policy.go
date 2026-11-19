package managed

import (
	"errors"
	"fmt"
	"math"
	"strings"
)

const (
	ApplicationPoliciesCapability = "detection.application_policies"
	MaxApplicationPolicies        = 64
)

// ApplicationPolicy is the frozen detection and response for one system service.
// The enclosing signed policy binds all applications to the same enrollment.
type ApplicationPolicy struct {
	Service       string          `json:"service"`
	PolicyID      string          `json:"policy_id"`
	PolicyVersion uint64          `json:"policy_version"`
	Detection     DetectionPolicy `json:"detection"`
	Response      ResponsePolicy  `json:"response"`
}

func ValidApplicationService(service string) bool {
	return len(service) > len(".service") && strings.HasSuffix(service, ".service") && validName(service, false)
}

func validateApplications(applications []ApplicationPolicy, fallbackMode string) error {
	if len(applications) > MaxApplicationPolicies {
		return errors.New("too many application policies")
	}
	if len(applications) > 0 && fallbackMode != "observe" {
		return errors.New("application policies require a host fallback response of observe")
	}
	services := make(map[string]bool, len(applications))
	for _, app := range applications {
		if !ValidApplicationService(app.Service) || services[app.Service] ||
			!validIdentifier(app.PolicyID, 128) || app.PolicyVersion == 0 || app.PolicyVersion > math.MaxInt64 {
			return errors.New("invalid or duplicate application policy identity")
		}
		services[app.Service] = true
		if err := app.validate(); err != nil {
			return fmt.Errorf("application %s: %w", app.Service, err)
		}
	}
	return nil
}

func (app ApplicationPolicy) validate() error {
	d := app.Detection
	if len(d.WebServices) != 1 || d.WebServices[0] != app.Service || len(d.WebExecutables) != 0 || d.PrivilegeRules || d.RootExecAlerts != "" {
		return errors.New("application detection must be restricted to its own service")
	}
	for _, control := range d.ServiceRuleControls {
		if control.Service != app.Service {
			return errors.New("application rule control targets a different service")
		}
	}
	if d.ServiceObservations != nil {
		for _, scope := range *d.ServiceObservations {
			if scope.Service != app.Service {
				return errors.New("application observation targets a different service")
			}
		}
	}
	return validateDetectionAndResponse(d, app.Response)
}
