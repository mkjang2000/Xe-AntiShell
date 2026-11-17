//go:build !linux

package response

import (
	"context"
	"errors"
	"time"
	"xe-antishell/internal/model"
)

const CapabilityName = "response.terminate"
const MaxEventAge = 3 * time.Second

func Capability(bool) model.Capability {
	return model.Capability{Name: CapabilityName, State: model.CapabilityUnsupported, Implementation: "implemented", RuntimeState: "inactive", Reason: "pidfd termination requires Linux"}
}
func Terminate(context.Context, model.Event, time.Time) error {
	return errors.New("response refused: pidfd termination requires Linux")
}
