// Package errors provides standardized error types for better-auth.
//
// This package defines the error hierarchy for Better Auth following
// the specification in ERRORS.md in the root repository.
package errors

import (
	"encoding/json"
	"fmt"
)

// BetterAuthError represents a standardized error with code and context
type BetterAuthError struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Context map[string]any `json:"context,omitempty"`
}

// Error implements the error interface
func (e *BetterAuthError) Error() string {
	return e.Message
}

// MarshalJSON implements custom JSON marshaling
func (e *BetterAuthError) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"error": map[string]any{
			"code":    e.Code,
			"message": e.Message,
			"context": e.Context,
		},
	})
}

// newError creates a new BetterAuthError
func newError(code, message string) *BetterAuthError {
	return &BetterAuthError{
		Code:    code,
		Message: message,
		Context: make(map[string]any),
	}
}

// withContext adds context to an error
func (e *BetterAuthError) withContext(key string, value any) *BetterAuthError {
	if e.Context == nil {
		e.Context = make(map[string]any)
	}
	e.Context[key] = value
	return e
}

// ============================================================================
// Validation Errors
// ============================================================================

// NewInvalidMessageError creates an error for malformed messages
func NewInvalidMessageError(field, details string) error {
	message := "Message structure is invalid or malformed"
	if field != "" {
		message = fmt.Sprintf("Message structure is invalid: %s", field)
		if details != "" {
			message = fmt.Sprintf("%s (%s)", message, details)
		}
	}

	err := newError("BA101", message)
	if field != "" {
		err.withContext("field", field)
	}
	if details != "" {
		err.withContext("details", details)
	}
	return err
}

// NewInvalidIdentityError creates an error for identity verification failures
func NewInvalidIdentityError(provided, details string) error {
	err := newError("BA102", "Identity verification failed")
	if provided != "" {
		err.withContext("provided", provided)
	}
	if details != "" {
		err.withContext("details", details)
	}
	return err
}

// NewInvalidDeviceError creates an error for device hash validation failures
func NewInvalidDeviceError(provided, calculated string) error {
	err := newError("BA103", "Device hash does not match hash(publicKey || rotationHash)")
	if provided != "" {
		err.withContext("provided", provided)
	}
	if calculated != "" {
		err.withContext("calculated", calculated)
	}
	return err
}

// NewInvalidHashError creates an error for hash validation failures
func NewInvalidHashError(expected, actual, hashType string) error {
	err := newError("BA104", "Hash validation failed")
	if expected != "" {
		err.withContext("expected", expected)
	}
	if actual != "" {
		err.withContext("actual", actual)
	}
	if hashType != "" {
		err.withContext("hashType", hashType)
	}
	return err
}

// ============================================================================
// Cryptographic Errors
// ============================================================================

// NewIncorrectNonceError creates an error for nonce mismatches
func NewIncorrectNonceError(expected, actual string) error {
	truncate := func(s string) string {
		if len(s) > 16 {
			return s[:16] + "..."
		}
		return s
	}

	err := newError("BA203", "Response nonce does not match request nonce")
	if expected != "" {
		err.withContext("expected", truncate(expected))
	}
	if actual != "" {
		err.withContext("actual", truncate(actual))
	}
	return err
}

// ============================================================================
// Authentication/Authorization Errors
// ============================================================================

// NewMismatchedIdentitiesError creates an error for identity mismatches
func NewMismatchedIdentitiesError(linkContainerIdentity, requestIdentity string) error {
	err := newError("BA302", "Link container identity does not match request identity")
	if linkContainerIdentity != "" {
		err.withContext("linkContainerIdentity", linkContainerIdentity)
	}
	if requestIdentity != "" {
		err.withContext("requestIdentity", requestIdentity)
	}
	return err
}

// ============================================================================
// Token Errors
// ============================================================================

// NewExpiredTokenError creates an error for expired tokens
func NewExpiredTokenError(expiryTime, currentTime, tokenType string) error {
	err := newError("BA401", "Token has expired")
	if expiryTime != "" {
		err.withContext("expiryTime", expiryTime)
	}
	if currentTime != "" {
		err.withContext("currentTime", currentTime)
	}
	if tokenType != "" {
		err.withContext("tokenType", tokenType)
	}
	return err
}

// NewFutureTokenError creates an error for tokens issued in the future
func NewFutureTokenError(issuedAt, currentTime string, timeDifference float64) error {
	err := newError("BA403", "Token issued_at timestamp is in the future")
	if issuedAt != "" {
		err.withContext("issuedAt", issuedAt)
	}
	if currentTime != "" {
		err.withContext("currentTime", currentTime)
	}
	if timeDifference != 0 {
		err.withContext("timeDifference", timeDifference)
	}
	return err
}

// ============================================================================
// Temporal Errors
// ============================================================================

// NewStaleRequestError creates an error for old requests
func NewStaleRequestError(requestTimestamp, currentTime string, maximumAge int64) error {
	err := newError("BA501", "Request timestamp is too old")
	if requestTimestamp != "" {
		err.withContext("requestTimestamp", requestTimestamp)
	}
	if currentTime != "" {
		err.withContext("currentTime", currentTime)
	}
	if maximumAge != 0 {
		err.withContext("maximumAge", maximumAge)
	}
	return err
}

// NewFutureRequestError creates an error for requests from the future
func NewFutureRequestError(requestTimestamp, currentTime string, timeDifference float64) error {
	err := newError("BA502", "Request timestamp is in the future")
	if requestTimestamp != "" {
		err.withContext("requestTimestamp", requestTimestamp)
	}
	if currentTime != "" {
		err.withContext("currentTime", currentTime)
	}
	if timeDifference != 0 {
		err.withContext("timeDifference", timeDifference)
	}
	return err
}
