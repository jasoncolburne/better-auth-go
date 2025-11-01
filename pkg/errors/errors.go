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
	Code    string                 `json:"code"`
	Message string                 `json:"message"`
	Context map[string]interface{} `json:"context,omitempty"`
}

// Error implements the error interface
func (e *BetterAuthError) Error() string {
	return e.Message
}

// MarshalJSON implements custom JSON marshaling
func (e *BetterAuthError) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"error": map[string]interface{}{
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
		Context: make(map[string]interface{}),
	}
}

// withContext adds context to an error
func (e *BetterAuthError) withContext(key string, value interface{}) *BetterAuthError {
	if e.Context == nil {
		e.Context = make(map[string]interface{})
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

// NewSignatureVerificationError creates an error for signature verification failures
func NewSignatureVerificationError(publicKey, signedData string) error {
	err := newError("BA201", "Signature verification failed")
	if publicKey != "" {
		err.withContext("publicKey", publicKey)
	}
	if signedData != "" {
		err.withContext("signedData", signedData)
	}
	return err
}

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

// NewExpiredNonceError creates an error for expired authentication challenges
func NewExpiredNonceError(nonceTimestamp, currentTime, expirationWindow string) error {
	err := newError("BA204", "Authentication challenge has expired")
	if nonceTimestamp != "" {
		err.withContext("nonceTimestamp", nonceTimestamp)
	}
	if currentTime != "" {
		err.withContext("currentTime", currentTime)
	}
	if expirationWindow != "" {
		err.withContext("expirationWindow", expirationWindow)
	}
	return err
}

// NewNonceReplayError creates an error for nonce replay attacks
func NewNonceReplayError(nonce, previousUsageTimestamp string) error {
	truncate := func(s string) string {
		if len(s) > 16 {
			return s[:16] + "..."
		}
		return s
	}

	err := newError("BA205", "Nonce has already been used (replay attack detected)")
	if nonce != "" {
		err.withContext("nonce", truncate(nonce))
	}
	if previousUsageTimestamp != "" {
		err.withContext("previousUsageTimestamp", previousUsageTimestamp)
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

// NewPermissionDeniedError creates an error for insufficient permissions
func NewPermissionDeniedError(requiredPermissions, actualPermissions []string, operation string) error {
	err := newError("BA303", "Insufficient permissions for requested operation")
	if requiredPermissions != nil {
		err.withContext("requiredPermissions", requiredPermissions)
	}
	if actualPermissions != nil {
		err.withContext("actualPermissions", actualPermissions)
	}
	if operation != "" {
		err.withContext("operation", operation)
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

// NewInvalidTokenError creates an error for invalid token structure
func NewInvalidTokenError(details string) error {
	err := newError("BA402", "Token structure or format is invalid")
	if details != "" {
		err.withContext("details", details)
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

// NewClockSkewError creates an error for clock differences
func NewClockSkewError(clientTime, serverTime string, timeDifference, maxTolerance float64) error {
	err := newError("BA503", "Client and server clock difference exceeds tolerance")
	if clientTime != "" {
		err.withContext("clientTime", clientTime)
	}
	if serverTime != "" {
		err.withContext("serverTime", serverTime)
	}
	if timeDifference != 0 {
		err.withContext("timeDifference", timeDifference)
	}
	if maxTolerance != 0 {
		err.withContext("maxTolerance", maxTolerance)
	}
	return err
}

// ============================================================================
// Storage Errors
// ============================================================================

// NewNotFoundError creates an error for missing resources
func NewNotFoundError(resourceType, resourceIdentifier string) error {
	message := "Resource not found"
	if resourceType != "" {
		message = fmt.Sprintf("Resource not found: %s", resourceType)
	}

	err := newError("BA601", message)
	if resourceType != "" {
		err.withContext("resourceType", resourceType)
	}
	if resourceIdentifier != "" {
		err.withContext("resourceIdentifier", resourceIdentifier)
	}
	return err
}

// NewAlreadyExistsError creates an error for duplicate resources
func NewAlreadyExistsError(resourceType, resourceIdentifier string) error {
	message := "Resource already exists"
	if resourceType != "" {
		message = fmt.Sprintf("Resource already exists: %s", resourceType)
	}

	err := newError("BA602", message)
	if resourceType != "" {
		err.withContext("resourceType", resourceType)
	}
	if resourceIdentifier != "" {
		err.withContext("resourceIdentifier", resourceIdentifier)
	}
	return err
}

// NewStorageUnavailableError creates an error for storage backend failures
func NewStorageUnavailableError(backendType, connectionDetails, backendError string) error {
	err := newError("BA603", "Storage backend is unavailable")
	if backendType != "" {
		err.withContext("backendType", backendType)
	}
	if connectionDetails != "" {
		err.withContext("connectionDetails", connectionDetails)
	}
	if backendError != "" {
		err.withContext("backendError", backendError)
	}
	return err
}

// NewStorageCorruptionError creates an error for corrupted data
func NewStorageCorruptionError(resourceType, resourceIdentifier, corruptionDetails string) error {
	err := newError("BA604", "Stored data is corrupted or invalid")
	if resourceType != "" {
		err.withContext("resourceType", resourceType)
	}
	if resourceIdentifier != "" {
		err.withContext("resourceIdentifier", resourceIdentifier)
	}
	if corruptionDetails != "" {
		err.withContext("corruptionDetails", corruptionDetails)
	}
	return err
}

// ============================================================================
// Encoding Errors
// ============================================================================

// NewSerializationError creates an error for serialization failures
func NewSerializationError(messageType, format, details string) error {
	err := newError("BA701", "Failed to serialize message")
	if messageType != "" {
		err.withContext("messageType", messageType)
	}
	if format != "" {
		err.withContext("format", format)
	}
	if details != "" {
		err.withContext("details", details)
	}
	return err
}

// NewDeserializationError creates an error for deserialization failures
func NewDeserializationError(messageType, rawData, details string) error {
	truncateData := func(s string) string {
		if len(s) > 100 {
			return s[:100] + "..."
		}
		return s
	}

	err := newError("BA702", "Failed to deserialize message")
	if messageType != "" {
		err.withContext("messageType", messageType)
	}
	if rawData != "" {
		err.withContext("rawData", truncateData(rawData))
	}
	if details != "" {
		err.withContext("details", details)
	}
	return err
}

// NewCompressionError creates an error for compression/decompression failures
func NewCompressionError(operation string, dataSize int, details string) error {
	err := newError("BA703", "Failed to compress or decompress data")
	if operation != "" {
		err.withContext("operation", operation)
	}
	if dataSize != 0 {
		err.withContext("dataSize", dataSize)
	}
	if details != "" {
		err.withContext("details", details)
	}
	return err
}

// ============================================================================
// Network Errors (Client-Only)
// ============================================================================

// NewConnectionError creates an error for connection failures
func NewConnectionError(serverURL, details string) error {
	err := newError("BA801", "Failed to connect to server")
	if serverURL != "" {
		err.withContext("serverUrl", serverURL)
	}
	if details != "" {
		err.withContext("details", details)
	}
	return err
}

// NewTimeoutError creates an error for request timeouts
func NewTimeoutError(timeoutDuration int64, endpoint string) error {
	err := newError("BA802", "Request timed out")
	if timeoutDuration != 0 {
		err.withContext("timeoutDuration", timeoutDuration)
	}
	if endpoint != "" {
		err.withContext("endpoint", endpoint)
	}
	return err
}

// NewProtocolError creates an error for HTTP protocol violations
func NewProtocolError(httpStatusCode int, details string) error {
	err := newError("BA803", "Invalid HTTP response or protocol violation")
	if httpStatusCode != 0 {
		err.withContext("httpStatusCode", httpStatusCode)
	}
	if details != "" {
		err.withContext("details", details)
	}
	return err
}

// ============================================================================
// Protocol Errors
// ============================================================================

// NewInvalidStateError creates an error for invalid state transitions
func NewInvalidStateError(currentState, attemptedOperation, requiredState string) error {
	err := newError("BA901", "Operation not allowed in current state")
	if currentState != "" {
		err.withContext("currentState", currentState)
	}
	if attemptedOperation != "" {
		err.withContext("attemptedOperation", attemptedOperation)
	}
	if requiredState != "" {
		err.withContext("requiredState", requiredState)
	}
	return err
}

// NewRotationError creates an error for key rotation failures
func NewRotationError(rotationType, details string) error {
	err := newError("BA902", "Key rotation failed")
	if rotationType != "" {
		err.withContext("rotationType", rotationType)
	}
	if details != "" {
		err.withContext("details", details)
	}
	return err
}

// NewRecoveryError creates an error for account recovery failures
func NewRecoveryError(details string) error {
	err := newError("BA903", "Account recovery failed")
	if details != "" {
		err.withContext("details", details)
	}
	return err
}

// NewDeviceRevokedError creates an error for revoked devices
func NewDeviceRevokedError(deviceIdentifier, revocationTimestamp string) error {
	err := newError("BA904", "Device has been revoked")
	if deviceIdentifier != "" {
		err.withContext("deviceIdentifier", deviceIdentifier)
	}
	if revocationTimestamp != "" {
		err.withContext("revocationTimestamp", revocationTimestamp)
	}
	return err
}

// NewIdentityDeletedError creates an error for deleted identities
func NewIdentityDeletedError(identityIdentifier, deletionTimestamp string) error {
	err := newError("BA905", "Identity has been deleted")
	if identityIdentifier != "" {
		err.withContext("identityIdentifier", identityIdentifier)
	}
	if deletionTimestamp != "" {
		err.withContext("deletionTimestamp", deletionTimestamp)
	}
	return err
}
