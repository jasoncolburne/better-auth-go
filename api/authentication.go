package api

import (
	"encoding/json"

	"github.com/jasoncolburne/better-auth-go/pkg/messages"
)

func (ba *BetterAuth) BeginAuthentication(request *messages.BeginAuthenticationRequest) (string, error) {
	nonce, err := ba.stores.authenticationNonce.Generate(
		request.Payload.Identification.AccountId,
	)
	if err != nil {
		return "", err
	}

	publicKey, err := ba.crypto.keyPairs.response.Public()
	if err != nil {
		return "", err
	}

	publicKeyDigest := ba.crypto.digest.Sum([]byte(publicKey))

	payload := messages.BeginAuthenticationResponsePayload{
		Authentication: messages.BeginAuthenticationResponseAuthentication{
			Nonce: nonce,
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

	message := messages.BeginAuthenticationResponse{
		Payload:   payload,
		Signature: signature,
	}

	bytes, err := json.Marshal(message)
	if err != nil {
		return "", err
	}

	return string(bytes), nil
}

func (ba *BetterAuth) CompleteAuthentication(request *messages.CompleteAuthenticationRequest) (string, error) {
	accountId, err := ba.stores.authenticationNonce.Verify(request.Payload.Authentication.Nonce)
	if err != nil {
		return "", err
	}

	authenticationPublicKey, err := ba.stores.authenticationKey.Public(
		accountId,
		request.Payload.Identification.DeviceId,
	)
	if err != nil {
		return "", err
	}

	requestPayloadBytes, err := json.Marshal(request.Payload)
	if err != nil {
		return "", err
	}

	if err := ba.crypto.verification.Verify(
		request.Signature,
		authenticationPublicKey,
		requestPayloadBytes,
	); err != nil {
		return "", err
	}

	sessionId, err := ba.stores.refreshKey.Create(accountId, request.Payload.Refresh.PublicKey)
	if err != nil {
		return "", err
	}

	if err := ba.stores.refreshNonce.Create(sessionId, request.Payload.Refresh.Nonces.NextDigest); err != nil {
		return "", err
	}

	publicKey, err := ba.crypto.keyPairs.response.Public()
	if err != nil {
		return "", err
	}

	publicKeyDigest := ba.crypto.digest.Sum([]byte(publicKey))

	payload := messages.CompleteAuthenticationResponsePayload{
		Refresh: messages.CompleteAuthenticationResponseRefresh{
			SessionId: sessionId,
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

	message := messages.CompleteAuthenticationResponse{
		Payload:   payload,
		Signature: signature,
	}

	bytes, err := json.Marshal(message)
	if err != nil {
		return "", err
	}

	return string(bytes), nil
}

func (ba *BetterAuth) BeginPassphraseAuthentication(request *messages.BeginPassphraseAuthenticationRequest) (string, error) {
	accountId := request.Payload.Identification.AccountId

	salt, parameters, err := ba.stores.passphraseAuthenticationKey.GetDerivationMaterial(accountId)
	if err != nil {
		return "", err
	}

	nonce, err := ba.stores.authenticationNonce.Generate(accountId)
	if err != nil {
		return "", err
	}

	publicKey, err := ba.crypto.keyPairs.response.Public()
	if err != nil {
		return "", err
	}

	publicKeyDigest := ba.crypto.digest.Sum([]byte(publicKey))

	payload := messages.BeginPassphraseAuthenticationResponsePayload{
		PassphraseAuthentication: messages.BeginPassphraseAuthenticationResponsePassphraseAuthentication{
			Nonce:      nonce,
			Salt:       salt,
			Parameters: parameters,
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

	message := messages.BeginPassphraseAuthenticationResponse{
		Payload:   payload,
		Signature: signature,
	}

	bytes, err := json.Marshal(message)
	if err != nil {
		return "", err
	}

	return string(bytes), nil
}

func (ba *BetterAuth) CompletePassphraseAuthentication(request *messages.CompletePassphraseAuthenticationRequest) (string, error) {
	accountId, err := ba.stores.authenticationNonce.Verify(request.Payload.PassphraseAuthentication.Nonce)
	if err != nil {
		return "", err
	}

	if err := ba.stores.passphraseAuthenticationKey.VerifyPublicKey(
		accountId,
		request.Payload.PassphraseAuthentication.PublicKey,
	); err != nil {
		return "", err
	}

	requestPayloadBytes, err := json.Marshal(request.Payload)
	if err != nil {
		return "", err
	}

	if err := ba.crypto.passphraseVerification.Verify(request.Signature, request.Payload.PassphraseAuthentication.PublicKey, requestPayloadBytes); err != nil {
		return "", err
	}

	sessionId, err := ba.stores.refreshKey.Create(accountId, request.Payload.Refresh.PublicKey)
	if err != nil {
		return "", err
	}

	if err := ba.stores.refreshNonce.Create(sessionId, request.Payload.Refresh.Nonces.NextDigest); err != nil {
		return "", err
	}

	publicKey, err := ba.crypto.keyPairs.response.Public()
	if err != nil {
		return "", err
	}

	publicKeyDigest := ba.crypto.digest.Sum([]byte(publicKey))

	payload := messages.CompletePassphraseAuthenticationResponsePayload{
		Refresh: messages.CompletePassphraseAuthenticationResponseRefresh{
			SessionId: sessionId,
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

	message := messages.CompletePassphraseAuthenticationResponse{
		Payload:   payload,
		Signature: signature,
	}

	bytes, err := json.Marshal(message)
	if err != nil {
		return "", err
	}

	return string(bytes), nil
}
