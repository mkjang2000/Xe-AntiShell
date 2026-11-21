package managedclient

import (
	"context"
	"errors"
	"net/http"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

func (c *Client) RemoteRemoval(ctx context.Context) (*managed.SignedRemoteRemovalOrder, error) {
	if !c.authenticated {
		return nil, ErrIdentityRequired
	}
	var order managed.SignedRemoteRemovalOrder
	status, err := c.request(ctx, http.MethodGet, "/v1/remote-removal", "", nil, &order, 16<<10)
	if status == http.StatusNoContent || status == http.StatusNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, errors.New("central returned an invalid removal order response")
	}
	return &order, nil
}

func (c *Client) ClaimRemoteRemoval(ctx context.Context, claim managed.RemoteRemovalClaim) (managed.SignedRemovalGrant, error) {
	var grant managed.SignedRemovalGrant
	if !c.authenticated {
		return grant, ErrIdentityRequired
	}
	if err := claim.Validate(); err != nil {
		return grant, err
	}
	status, err := c.request(ctx, http.MethodPost, "/v1/remote-removal/claim", "", claim, &grant, 16<<10)
	if err == nil && status != http.StatusOK && status != http.StatusCreated {
		err = errors.New("central returned an invalid removal claim response")
	}
	return grant, err
}

func (c *Client) ReportRemoteRemoval(ctx context.Context, report managed.RemoteRemovalReport) error {
	if !c.authenticated {
		return ErrIdentityRequired
	}
	if err := report.Validate(); err != nil {
		return err
	}
	status, err := c.request(ctx, http.MethodPost, "/v1/remote-removal/report", "", report, nil, 16<<10)
	if err == nil && status != http.StatusNoContent {
		return errors.New("central did not acknowledge the remote removal report")
	}
	return err
}
