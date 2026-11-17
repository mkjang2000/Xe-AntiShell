package managedclient

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

func (c *Client) DesiredUpdate(ctx context.Context) (*managed.SignedUpdatePlan, error) {
	if !c.authenticated {
		return nil, ErrIdentityRequired
	}
	var value managed.SignedUpdatePlan
	status, err := c.request(ctx, http.MethodGet, "/v1/update", "", nil, &value, managed.MaxUpdateBytes)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNoContent {
		return nil, nil
	}
	return &value, nil
}

func (c *Client) UpdateInventory(ctx context.Context, value managed.UpdateInventory) error {
	if !c.authenticated {
		return ErrIdentityRequired
	}
	if err := value.Validate(); err != nil {
		return err
	}
	_, err := c.request(ctx, http.MethodPost, "/v1/update/status", "", value, nil, 16<<10)
	return err
}

func (c *Client) ClaimUpdate(ctx context.Context, claim managed.UpdateClaim) (managed.SignedUpdateAuthorization, error) {
	var value managed.SignedUpdateAuthorization
	if !c.authenticated {
		return value, ErrIdentityRequired
	}
	if err := claim.Validate(); err != nil {
		return value, err
	}
	_, err := c.request(ctx, http.MethodPost, "/v1/update/claim", "", claim, &value, managed.MaxUpdateBytes)
	return value, err
}

func (c *Client) ReportUpdate(ctx context.Context, report managed.UpdateReport) error {
	if !c.authenticated {
		return ErrIdentityRequired
	}
	if err := report.Validate(); err != nil {
		return err
	}
	_, err := c.request(ctx, http.MethodPost, "/v1/update/report", "", report, nil, 16<<10)
	return err
}

// UpdateDownloadError carries only a fixed diagnostic, never response bytes.
type UpdateDownloadError struct{ Code string }

func (e *UpdateDownloadError) Error() string { return e.Code }

// DownloadUpdateArtifact uses the existing pinned mTLS transport but a separate
// bounded streaming deadline. The peer cannot select a URL or redirect target.
func (c *Client) DownloadUpdateArtifact(ctx context.Context, release managed.UpdateRelease, output io.Writer) error {
	if !c.authenticated {
		return ErrIdentityRequired
	}
	if err := release.Validate(); err != nil {
		return err
	}
	u := c.base
	u.Path = strings.TrimRight(u.Path, "/") + "/v1/update/artifacts/" + release.SHA256
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return &UpdateDownloadError{"download_failed"}
	}
	request.Header.Set("Accept", "application/octet-stream")
	client := *c.http
	client.Timeout = 5 * time.Minute
	response, err := client.Do(request)
	if err != nil {
		return &UpdateDownloadError{"download_failed"}
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return &StatusError{Code: response.StatusCode}
	}
	if encoding := response.Header.Get("Content-Encoding"); encoding != "" && encoding != "identity" {
		return &UpdateDownloadError{"download_failed"}
	}
	if response.ContentLength >= 0 && response.ContentLength != release.Size {
		return &UpdateDownloadError{"size_mismatch"}
	}
	hash := sha256.New()
	written, err := io.Copy(io.MultiWriter(output, hash), io.LimitReader(response.Body, release.Size+1))
	if err != nil {
		return &UpdateDownloadError{"download_failed"}
	}
	if written != release.Size {
		return &UpdateDownloadError{"size_mismatch"}
	}
	if !strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), release.SHA256) {
		return &UpdateDownloadError{"hash_mismatch"}
	}
	return nil
}

func UpdateUnsupported(err error) bool {
	var status *StatusError
	return errors.As(err, &status) && (status.Code == http.StatusNotFound || status.Code == http.StatusNotImplemented)
}
