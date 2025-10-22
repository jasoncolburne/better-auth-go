package api

import (
	"context"
	"fmt"
	"strings"

	"github.com/jasoncolburne/better-auth-go/pkg/messages"
)

func (ba *BetterAuthServer[AttributesType]) RequestSession(ctx context.Context, message string) (string, error) {
	request, err := messages.ParseRequestSessionRequest(message)
	if err != nil {
		return "", err
	}

	nonce, err := ba.store.Authentication.Nonce.Generate(
		ctx,
		request.Payload.Request.Authentication.Identity,
	)
	if err != nil {
		return "", err
	}

	serverIdentity, err := ba.crypto.KeyPair.Response.Identity()
	if err != nil {
		return "", err
	}

	response := messages.NewRequestSessionResponse(
		messages.RequestSessionResponsePayload{
			Authentication: messages.RequestSessionResponseAuthentication{
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

func (ba *BetterAuthServer[AttributesType]) CreateSession(ctx context.Context, message string, attributes AttributesType) (string, error) {
	request, err := messages.ParseCreateSessionRequest(message)
	if err != nil {
		return "", err
	}

	identity, err := ba.store.Authentication.Nonce.Verify(
		ctx,
		request.Payload.Request.Authentication.Nonce,
	)
	if err != nil {
		return "", err
	}

	authenticationPublicKey, err := ba.store.Authentication.Key.Public(
		ctx,
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
		request.Payload.Request.Authentication.Device,
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

	response := messages.NewCreateSessionResponse(
		messages.CreateSessionResponsePayload{
			Access: messages.CreateSessionResponseAccess{
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

func (ba *BetterAuthServer[AttributesType]) RefreshSession(ctx context.Context, message string) (string, error) {
	request, err := messages.ParseRefreshSessionRequest(message)
	if err != nil {
		return "", err
	}

	if err := request.Verify(ba.crypto.Verifier, request.Payload.Request.Access.PublicKey); err != nil {
		return "", err
	}

	tokenString := request.Payload.Request.Access.Token
	token, err := messages.ParseAccessToken[AttributesType](
		tokenString,
		ba.encoding.TokenEncoder,
	)
	if err != nil {
		return "", err
	}

	accessVerificationKey, err := ba.store.Access.VerificationKey.Get(ctx, token.ServerIdentity)
	if err != nil {
		return "", err
	}

	accessPublicKey, err := accessVerificationKey.Public()
	if err != nil {
		return "", err
	}

	if err := token.VerifySignature(ba.crypto.KeyPair.Access.Verifier(), accessPublicKey); err != nil {
		return "", err
	}

	hash := ba.crypto.Hasher.Sum([]byte(request.Payload.Request.Access.PublicKey))
	if !strings.EqualFold(hash, token.RotationHash) {
		return "", fmt.Errorf("hash mismatch")
	}

	now := ba.encoding.Timestamper.Now()
	refreshExpiry, err := ba.encoding.Timestamper.Parse(token.RefreshExpiry)
	if err != nil {
		return "", err
	}

	if now.After(refreshExpiry) {
		return "", fmt.Errorf("refresh has expired")
	}

	if err := ba.store.Access.KeyHash.Reserve(ctx, hash); err != nil {
		return "", err
	}

	later := now.Add(ba.expiry.Access)

	issuedAt := ba.encoding.Timestamper.Format(now)
	expiry := ba.encoding.Timestamper.Format(later)

	accessServerIdentity, err := ba.crypto.KeyPair.Access.Identity()
	if err != nil {
		return "", err
	}

	accessToken := messages.NewAccessToken(
		accessServerIdentity,
		token.Device,
		token.Identity,
		request.Payload.Request.Access.PublicKey,
		request.Payload.Request.Access.RotationHash,
		issuedAt,
		expiry,
		token.RefreshExpiry,
		token.Attributes,
	)

	if err := accessToken.Sign(ba.crypto.KeyPair.Access); err != nil {
		return "", err
	}

	serializedToken, err := accessToken.SerializeToken(ba.encoding.TokenEncoder)
	if err != nil {
		return "", err
	}

	serverIdentity, err := ba.crypto.KeyPair.Response.Identity()
	if err != nil {
		return "", err
	}

	response := messages.NewRefreshSessionResponse(
		messages.RefreshSessionResponsePayload{
			Access: messages.RefreshSessionResponseAccess{
				Token: serializedToken,
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
