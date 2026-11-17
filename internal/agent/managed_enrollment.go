package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"xe-antishell/internal/managedclient"
)

type enrollmentStage string

const (
	enrollmentPendingIdentityMismatch  enrollmentStage = "pending_identity_mismatch"
	enrollmentExistingIdentityMismatch enrollmentStage = "existing_identity_mismatch"
	enrollmentLocalState               enrollmentStage = "local_state"
	enrollmentInvalidSetup             enrollmentStage = "invalid_setup"
	enrollmentCentralRequest           enrollmentStage = "central_request"
	enrollmentInvalidResponse          enrollmentStage = "invalid_response"
)

// Callers hold enrollmentMu so an older attempt cannot overwrite a later
// attempt's recovery. Neither status nor journal entries retain raw errors.
func (s *Service) recordEnrollmentResult(stage enrollmentStage, err error) {
	if err == nil {
		s.managedError("enrollment", "")
		return
	}
	message, category, status := enrollmentFailureSummary(stage, err)
	s.managedError("enrollment", message)
	attributes := []any{"stage", string(stage), "category", category}
	if status != 0 {
		attributes = append(attributes, "http_status", status)
	}
	slog.Warn("central enrollment failed", attributes...)
}

func enrollmentFailureSummary(stage enrollmentStage, err error) (message, category string, status int) {
	switch {
	case errors.Is(err, context.Canceled):
		return "central enrollment canceled", "canceled", 0
	case errors.Is(err, context.DeadlineExceeded):
		return "central enrollment deadline exceeded", "timeout", 0
	}
	switch stage {
	case enrollmentPendingIdentityMismatch:
		return "central enrollment blocked: pending identity differs from supplied central identity", "pending_identity_mismatch", 0
	case enrollmentExistingIdentityMismatch:
		return "central enrollment blocked: agent is already enrolled with a different identity or recovery code", "existing_identity_mismatch", 0
	case enrollmentLocalState:
		return "central enrollment failed: local enrollment state could not be read or saved", "storage", 0
	case enrollmentInvalidSetup:
		return "central enrollment failed: invalid configuration, local identity, or recovery code", "invalid_setup", 0
	case enrollmentInvalidResponse:
		return "central enrollment failed: response does not match the pinned trust and local identity", "invalid_response", 0
	case enrollmentCentralRequest:
		var response *managedclient.StatusError
		if errors.As(err, &response) && response != nil && response.Code >= 100 && response.Code <= 599 {
			return fmt.Sprintf("central enrollment rejected (HTTP %d)", response.Code), "http_status", response.Code
		}
		category = managedclient.TransportCategory(err)
		var description string
		switch category {
		case "dns":
			description = "DNS lookup failed"
		case "connection_refused":
			description = "connection refused"
		case "network_unreachable":
			description = "network unreachable"
		case "permission_denied":
			description = "network permission denied"
		case "timeout":
			description = "connection timed out"
		case "certificate_untrusted":
			description = "server certificate is not trusted"
		case "certificate_hostname":
			description = "server certificate hostname mismatch"
		case "certificate_invalid":
			description = "server certificate is invalid"
		case "tls":
			description = "TLS handshake failed"
		case "connection":
			description = "connection failed"
		}
		if description != "" {
			return "central enrollment failed: " + description, category, 0
		}
		return "central enrollment failed: request or response is invalid", "invalid_request_or_response", 0
	default:
		return "central enrollment failed", "unknown", 0
	}
}
