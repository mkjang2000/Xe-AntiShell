package managedclient

import (
	"context"
	"net/http"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

func (c *Client) AgentConfiguration(ctx context.Context) (*managed.SignedAgentConfiguration, error) {
	if !c.authenticated {
		return nil, ErrIdentityRequired
	}
	var value managed.SignedAgentConfiguration
	status, err := c.request(ctx, http.MethodGet, "/v1/agent-configuration", "", nil, &value, managed.MaxAgentConfigurationBytes)
	if status == http.StatusNotFound || status == http.StatusNoContent {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &value, nil
}
