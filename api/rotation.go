package api

import (
	"encoding/json"

	"github.com/jasoncolburne/better-auth-go/pkg/messages"
)

func (ba *BetterAuth) RotateAuthenticationKey(request *messages.RotateAuthenticationKeyRequest) (string, error) {
	requestPayloadBytes, err := json.Marshal(request.Payload)
	if err != nil {
		return "", err
	}

	if err := ba.crypto.verification.Verify(
		request.Signature,
		request.Payload.Authentication.PublicKeys.Current,
		requestPayloadBytes,
	); err != nil {
		return "", err
	}

	if err := ba.stores.authenticationKey.Rotate(
		request.Payload.Identification.AccountId,
		request.Payload.Identification.DeviceId,
		request.Payload.Authentication.PublicKeys.Current,
		request.Payload.Authentication.PublicKeys.NextDigest,
	); err != nil {
		return "", err
	}

	publicKey, err := ba.crypto.keyPairs.response.Public()
	if err != nil {
		return "", err
	}

	publicKeyDigest := ba.crypto.digest.Sum([]byte(publicKey))

	payload := messages.RotateAuthenticationKeyResponsePayload{
		Success:         true,
		PublicKeyDigest: publicKeyDigest,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	signature, err := ba.crypto.keyPairs.response.Sign(payloadBytes)
	if err != nil {
		return "", err
	}

	message := messages.RotateAuthenticationKeyResponse{
		Payload:   payload,
		Signature: signature,
	}

	bytes, err := json.Marshal(message)
	if err != nil {
		return "", err
	}

	return string(bytes), nil
}
