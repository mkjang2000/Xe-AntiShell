package managedclient

import (
	"context"
	"net/http"

	contract "github.com/mkjang2000/Xe-AntiShell/protocol/integrity"
)

func (c *Client) FileIntegrityAssignment(ctx context.Context) (*contract.Assignment, error) {
	if !c.authenticated {
		return nil, ErrIdentityRequired
	}
	var a contract.Assignment
	code, err := c.request(ctx, http.MethodGet, "/v1/integrity/files", "", nil, &a, contract.MaxMessage)
	if err != nil {
		return nil, err
	}
	if code == http.StatusNoContent {
		return nil, nil
	}
	return &a, nil
}

func (c *Client) SubmitFileIntegrity(ctx context.Context, r contract.Report) error {
	if !c.authenticated {
		return ErrIdentityRequired
	}
	_, err := c.request(ctx, http.MethodPost, "/v1/integrity/files", "", r, nil, 1024)
	return err
}
