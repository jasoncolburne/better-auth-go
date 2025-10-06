package api

import "github.com/jasoncolburne/better-auth-go/pkg/messages"

func (ba *BetterAuthServer[AttributesType]) CreateAccount(message string) (string, error) {
	request, err := messages.ParseCreateAccountRequest(message)
	if err != nil {
		return "", err
	}

	if err := request.Verify(ba.crypto.Verifier, request.Payload.Request.Authentication.PublicKey); err != nil {
		return "", err
	}

	identity := request.Payload.Request.Authentication.Identity

	if err := ba.encoding.IdentityVerifier.Verify(
		identity,
		request.Payload.Request.Authentication.PublicKey,
		request.Payload.Request.Authentication.RotationHash,
		&request.Payload.Request.Authentication.RecoveryHash,
	); err != nil {
		return "", err
	}

	hash := ba.crypto.Hasher.Sum(
		[]byte(request.Payload.Request.Authentication.PublicKey),
	)

	if hash != request.Payload.Request.Authentication.Device {
		return "", err
	}

	if err := ba.store.Recovery.Hash.Register(
		identity,
		request.Payload.Request.Authentication.RecoveryHash,
	); err != nil {
		return "", err
	}

	if err := ba.store.Authentication.Key.Register(
		identity,
		request.Payload.Request.Authentication.Device,
		request.Payload.Request.Authentication.PublicKey,
		request.Payload.Request.Authentication.RotationHash,
		false,
	); err != nil {
		return "", err
	}

	serverIdentity, err := ba.crypto.KeyPair.Response.Identity()
	if err != nil {
		return "", err
	}

	response := messages.NewCreateAccountResponse(
		messages.CreateAccountResponsePayload{},
		serverIdentity,
		request.Payload.Access.Nonce,
	)

	if err := response.Sign(ba.crypto.KeyPair.Response); err != nil {
		return "", err
	}

	reply, err := response.Serialize()
	if err != nil {
		return "", err
	}

	return reply, err
}
