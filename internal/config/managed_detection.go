package config

import "github.com/mkjang2000/Xe-AntiShell/protocol/managed"

// WithManagedDetection resolves signed fields and the host-local fallback for
// both the live detector and the isolated operator comparison.
func (c Config) WithManagedDetection(d managed.DetectionPolicy) Config {
	c.Detection = DetectionConfig{Enabled: d.Enabled, ExtendedProcessRules: d.ExtendedProcessRules, PrivilegeRules: d.PrivilegeRules, RootExecAlerts: d.RootExecAlerts, WebExecutables: d.WebExecutables, WebServices: d.WebServices, Shells: d.Shells, AllowedPairs: d.AllowedPairs, ServiceRuleControls: d.ServiceRuleControls}
	if d.ServiceObservations != nil {
		c.ServiceObservations = *d.ServiceObservations
	}
	return c
}
