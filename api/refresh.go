package api

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/jasoncolburne/better-auth-go/api/accesstoken"
	"github.com/jasoncolburne/better-auth-go/pkg/messages"
	orderedmap "github.com/wk8/go-ordered-map/v2"
)

func (ba *BetterAuth) RefreshAccessToken(request *messages.RefreshAccessTokenRequest, tokenAttributes *orderedmap.OrderedMap[string, any]) (string, error) {
	sessionId := request.Payload.Refresh.SessionId

	accountId, refreshPublicKey, err := ba.stores.refreshKey.Get(sessionId)
	if err != nil {
		return "", err
	}

	requestPayloadBytes, err := json.Marshal(request.Payload)
	if err != nil {
		return "", err
	}

	if err := ba.crypto.verification.Verify(
		request.Signature,
		refreshPublicKey,
		requestPayloadBytes,
	); err != nil {
		return "", err
	}

	if request.Payload.Refresh.Nonces.Current == nil {
		return "", fmt.Errorf("current nonce must be specified")
	}

	if err := ba.stores.refreshNonce.Evolve(
		sessionId,
		*request.Payload.Refresh.Nonces.Current,
		request.Payload.Refresh.Nonces.NextDigest,
	); err != nil {
		return "", err
	}

	issuedAt := time.Now().UTC()
	expiry := issuedAt.Add(time.Minute * 15) // TODO remove magic

	accessToken := messages.AccessToken{
		AccountId:  accountId,
		PublicKey:  request.Payload.Access.PublicKey,
		IssuedAt:   issuedAt.Format(time.RFC3339Nano),
		Expiry:     expiry.Format(time.RFC3339Nano),
		Attributes: tokenAttributes,
	}

	jsonToken, err := json.Marshal(accessToken)
	if err != nil {
		return "", err
	}

	tokenSignature, err := ba.crypto.keyPairs.access.Sign(jsonToken)
	if err != nil {
		return "", err
	}

	encodedToken, err := accesstoken.Encode(&accessToken, tokenSignature)
	if err != nil {
		return "", err
	}

	publicKey, err := ba.crypto.keyPairs.response.Public()
	if err != nil {
		return "", err
	}

	publicKeyDigest := ba.crypto.digest.Sum([]byte(publicKey))

	payload := messages.RefreshAccessTokenResponsePayload{
		Access: messages.RefreshAccessTokenResponseAccess{
			Token: encodedToken,
		},
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

	message := messages.RefreshAccessTokenResponse{
		Payload:   payload,
		Signature: signature,
	}

	bytes, err := json.Marshal(message)
	if err != nil {
		return "", err
	}

	return string(bytes), nil
}
