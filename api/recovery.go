package api

import "github.com/jasoncolburne/better-auth-go/pkg/messages"

func (ba *BetterAuthServer[AttributesType]) RecoverAccount(message string) (string, error) {
	request, err := messages.ParseRecoverAccountRequest(message)
	if err != nil {
		return "", err
	}

	if err := request.Verify(ba.crypto.Verifier, request.Payload.Request.Authentication.RecoveryKey); err != nil {
		return "", err
	}

	hash := ba.crypto.Hasher.Sum([]byte(request.Payload.Request.Authentication.RecoveryKey))
	if err := ba.store.Recovery.Hash.Validate(
		request.Payload.Request.Authentication.Identity,
		hash,
	); err != nil {
		return "", err
	}

	if err := ba.store.Authentication.Key.RevokeDevices(
		request.Payload.Request.Authentication.Identity,
	); err != nil {
		return "", err
	}

	if err := ba.store.Authentication.Key.Register(
		request.Payload.Request.Authentication.Identity,
		request.Payload.Request.Authentication.Device,
		request.Payload.Request.Authentication.PublicKey,
		request.Payload.Request.Authentication.RotationHash,
		true,
	); err != nil {
		return "", err
	}

	responseKeyHash, err := ba.responseKeyHash()
	if err != nil {
		return "", err
	}

	response := messages.NewRecoverAccountResponse(
		messages.RecoverAccountResponsePayload{},
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
