package managed

import (
	"crypto/ed25519"
	"errors"
	"time"
)

const (
	RemoteRemovalCapability  = "agent.remote_removal"
	RemoteRemovalContract    = "xeas-remote-removal/v2"
	MaxRemoteRemovalLifetime = 5 * time.Minute
)

type RemoteRemovalOrder struct {
	Contract     string    `json:"contract"`
	ID           string    `json:"order_id"`
	AgentID      string    `json:"agent_id"`
	EnrollmentID string    `json:"enrollment_id"`
	IssuedAt     time.Time `json:"issued_at"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type SignedRemoteRemovalOrder struct {
	Order     RemoteRemovalOrder `json:"order"`
	KeyID     string             `json:"key_id"`
	Signature string             `json:"signature"`
}

type RemoteRemovalClaim struct {
	OrderID     string `json:"order_id"`
	OperationID string `json:"operation_id"`
	Challenge   string `json:"challenge"`
}

type RemoteRemovalReport struct {
	OrderID string `json:"order_id"`
	State   string `json:"state"`
	Code    string `json:"code,omitempty"`
}

func (o RemoteRemovalOrder) Validate() error {
	if o.Contract != RemoteRemovalContract {
		return errors.New("unsupported remote removal authorization contract")
	}
	if !validIdentifier(o.ID, 160) || !validIdentifier(o.AgentID, 128) || !validIdentifier(o.EnrollmentID, 160) {
		return errors.New("invalid remote removal order identity")
	}
	if o.IssuedAt.IsZero() || !o.ExpiresAt.After(o.IssuedAt) || o.ExpiresAt.Sub(o.IssuedAt) > MaxRemoteRemovalLifetime {
		return errors.New("invalid remote removal order validity")
	}
	return nil
}

func (c RemoteRemovalClaim) Validate() error {
	if !validIdentifier(c.OrderID, 160) || !validIdentifier(c.OperationID, 160) || !validToken(c.Challenge, 32) {
		return errors.New("invalid remote removal claim")
	}
	return nil
}

func (r RemoteRemovalReport) Validate() error {
	if !validIdentifier(r.OrderID, 160) {
		return errors.New("invalid remote removal report identity")
	}
	switch r.State {
	case "started", "succeeded":
		if r.Code == "" {
			return nil
		}
	case "failed":
		switch r.Code {
		case "local_gate", "package_busy", "package_unavailable", "removal_failed", "verification_failed", "interrupted":
			return nil
		}
	}
	return errors.New("invalid remote removal report state or code")
}

func SignRemoteRemovalOrder(order RemoteRemovalOrder, keyID string, private ed25519.PrivateKey) (SignedRemoteRemovalOrder, error) {
	if err := order.Validate(); err != nil {
		return SignedRemoteRemovalOrder{}, err
	}
	signature, err := signValue("remote-removal-order", keyID, order, private, 16<<10)
	return SignedRemoteRemovalOrder{Order: order, KeyID: keyID, Signature: signature}, err
}

func VerifyRemoteRemovalOrder(signed SignedRemoteRemovalOrder, keys map[string]ed25519.PublicKey, agentID, enrollmentID string, now time.Time) (RemoteRemovalOrder, error) {
	if err := verifyValue("remote-removal-order", signed.KeyID, signed.Order, signed.Signature, keys, 16<<10); err != nil {
		return RemoteRemovalOrder{}, err
	}
	order := signed.Order
	if err := order.Validate(); err != nil {
		return RemoteRemovalOrder{}, err
	}
	if order.AgentID != agentID || order.EnrollmentID != enrollmentID {
		return RemoteRemovalOrder{}, errors.New("remote removal order does not match this enrollment")
	}
	if order.IssuedAt.After(now.Add(time.Minute)) || !now.Before(order.ExpiresAt) {
		return RemoteRemovalOrder{}, errors.New("remote removal order is expired or not yet valid")
	}
	return order, nil
}
