package api

import (
	"fmt"
	"strings"

	"github.com/jasoncolburne/better-auth-go/pkg/messages"
)

func (ba *BetterAuthServer[AttributesType]) RefreshAccessToken(message string) (string, error) {
	request, err := messages.ParseRefreshAccessTokenRequest(message)
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

	accessPublicKey, err := ba.crypto.KeyPair.Access.Public()
	if err != nil {
		return "", err
	}

	if err := token.VerifyToken(ba.crypto.KeyPair.Access.Verifier(), accessPublicKey, ba.encoding.Timestamper); err != nil {
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

	if err := ba.store.Access.KeyHash.Reserve(hash); err != nil {
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

	response := messages.NewRefreshAccessTokenResponse(
		messages.RefreshAccessTokenResponsePayload{
			Access: messages.RefreshAccessTokenResponseAccess{
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
