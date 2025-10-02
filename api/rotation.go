package api

import (
	"github.com/jasoncolburne/better-auth-go/pkg/messages"
)

func (ba *BetterAuthServer[AttributesType]) RotateAuthenticationKey(message string) (string, error) {
	request, err := messages.ParseRotateAuthenticationKeyRequest(message)
	if err != nil {
		return "", err
	}

	if err := request.Verify(ba.crypto.Verifier, request.Payload.Request.Authentication.PublicKey); err != nil {
		return "", err
	}

	if err := ba.store.Authentication.Key.Rotate(
		request.Payload.Request.Authentication.Identity,
		request.Payload.Request.Authentication.Device,
		request.Payload.Request.Authentication.PublicKey,
		&request.Payload.Request.Authentication.RotationHash,
	); err != nil {
		return "", err
	}

	responseKeyHash, err := ba.responseKeyHash()
	if err != nil {
		return "", err
	}

	response := messages.NewRotateAuthenticationKeyResponse(
		messages.RotateAuthenticationKeyResponsePayload{},
		responseKeyHash,
		request.Payload.Access.Nonce,
	)

	if err := response.Sign(ba.crypto.KeyPair.Response); err != nil {
		return "", err
	}

	reply, err := response.Serialize()
	if err != nil {
		return "", err
	}

	return reply, nil
}
