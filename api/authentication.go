package api

import (
	"github.com/jasoncolburne/better-auth-go/pkg/messages"
)

func (ba *BetterAuthServer[AttributesType]) StartAuthentication(message string) (string, error) {
	request, err := messages.ParseStartAuthenticationRequest(message)
	if err != nil {
		return "", err
	}

	nonce, err := ba.store.Authentication.Nonce.Generate(
		request.Payload.Request.Authentication.Identity,
	)
	if err != nil {
		return "", err
	}

	serverIdentity, err := ba.crypto.KeyPair.Response.Identity()
	if err != nil {
		return "", err
	}

	response := messages.NewStartAuthenticationResponse(
		messages.StartAuthenticationResponsePayload{
			Authentication: messages.StartAuthenticationResponseAuthentication{
				Nonce: nonce,
			},
		},
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

func (ba *BetterAuthServer[AttributesType]) FinishAuthentication(message string, attributes AttributesType) (string, error) {
	request, err := messages.ParseFinishAuthenticationRequest(message)
	if err != nil {
		return "", err
	}

	identity, err := ba.store.Authentication.Nonce.Verify(
		request.Payload.Request.Authentication.Nonce,
	)
	if err != nil {
		return "", err
	}

	authenticationPublicKey, err := ba.store.Authentication.Key.Public(
		identity,
		request.Payload.Request.Authentication.Device,
	)
	if err != nil {
		return "", err
	}

	if err := request.Verify(ba.crypto.Verifier, authenticationPublicKey); err != nil {
		return "", err
	}

	now := ba.encoding.Timestamper.Now()
	expiryTime := now.Add(ba.expiry.Access)
	refreshExpiryTime := now.Add(ba.expiry.Refresh)

	issuedAt := ba.encoding.Timestamper.Format(now)
	expiry := ba.encoding.Timestamper.Format(expiryTime)
	refreshExpiry := ba.encoding.Timestamper.Format(refreshExpiryTime)

	accessServerIdentity, err := ba.crypto.KeyPair.Access.Identity()
	if err != nil {
		return "", err
	}

	accessToken := messages.NewAccessToken(
		accessServerIdentity,
		identity,
		request.Payload.Request.Access.PublicKey,
		request.Payload.Request.Access.RotationHash,
		issuedAt,
		expiry,
		refreshExpiry,
		attributes,
	)

	if err := accessToken.Sign(ba.crypto.KeyPair.Access); err != nil {
		return "", err
	}

	token, err := accessToken.SerializeToken(ba.encoding.TokenEncoder)
	if err != nil {
		return "", err
	}

	serverIdentity, err := ba.crypto.KeyPair.Response.Identity()
	if err != nil {
		return "", err
	}

	response := messages.NewFinishAuthenticationResponse(
		messages.FinishAuthenticationResponsePayload{
			Access: messages.FinishAuthenticationResponseAccess{
				Token: token,
			},
		},
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

	return reply, nil
}
