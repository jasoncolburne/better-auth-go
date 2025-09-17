package api

import (
	"encoding/json"

	"github.com/jasoncolburne/better-auth-go/pkg/messages"
)

func (ba *BetterAuth) GenerateRegistrationMaterials() (string, error) {
	token, err := ba.stores.registrationToken.Generate()
	if err != nil {
		return "", err
	}

	publicKey, err := ba.crypto.keyPairs.response.Public()
	if err != nil {
		return "", err
	}

	publicKeyDigest := ba.crypto.digest.Sum([]byte(publicKey))

	payload := messages.RegistrationMaterialsPayload{
		Registration: messages.RegistrationMaterialsRegistration{
			Token: token,
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

	message := messages.RegistrationMaterials{
		Payload:   payload,
		Signature: signature,
	}

	bytes, err := json.Marshal(message)
	if err != nil {
		return "", err
	}

	return string(bytes), nil
}

func (ba *BetterAuth) GeneratePassphraseRegistrationMaterials() (string, error) {
	params := "$argon2id$v=19$m=262144,t=3,p=4$" // TODO remove magic
	salt, err := ba.crypto.salt.Generate128()
	if err != nil {
		return "", err
	}

	token, err := ba.stores.passphraseRegistrationToken.Generate(salt, params)
	if err != nil {
		return "", err
	}

	publicKey, err := ba.crypto.keyPairs.response.Public()
	if err != nil {
		return "", err
	}

	publicKeyDigest := ba.crypto.digest.Sum([]byte(publicKey))

	payload := messages.PassphraseRegistrationMaterialsPayload{
		Registration: messages.PassphraseRegistrationMaterialsRegistration{
			Token: token,
		},
		PassphraseAuthentication: messages.PassphraseRegistrationMaterialsPassphraseAuthentication{
			Parameters: params,
			Salt:       salt,
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

	message := messages.PassphraseRegistrationMaterials{
		Payload:   payload,
		Signature: signature,
	}

	bytes, err := json.Marshal(message)
	if err != nil {
		return "", err
	}

	return string(bytes), nil
}

func (ba *BetterAuth) RegisterAuthenticationKey(request *messages.RegisterAuthenticationKeyRequest) (string, error) {
	token := request.Payload.Registration.Token

	accountId, err := ba.stores.registrationToken.Validate(token)
	if err != nil {
		return "", err
	}

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

	if err := ba.stores.authenticationKey.Register(
		accountId,
		request.Payload.Identification.DeviceId,
		request.Payload.Authentication.PublicKeys.Current,
		request.Payload.Authentication.PublicKeys.NextDigest,
	); err != nil {
		return "", err
	}

	ba.stores.registrationToken.Invalidate(token)

	publicKey, err := ba.crypto.keyPairs.response.Public()
	if err != nil {
		return "", err
	}

	publicKeyDigest := ba.crypto.digest.Sum([]byte(publicKey))

	payload := messages.RegisterAuthenticationKeyResponsePayload{
		Identification: messages.RegisterAuthenticationKeyResponseIdentification{
			AccountId: accountId,
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

	message := messages.RegisterAuthenticationKeyResponse{
		Payload:   payload,
		Signature: signature,
	}

	bytes, err := json.Marshal(message)
	if err != nil {
		return "", err
	}

	return string(bytes), nil
}

func (ba *BetterAuth) RegisterPassphraseAuthenticationKey(request *messages.RegisterPassphraseAuthenticationKeyRequest) (string, error) {
	token := request.Payload.Registration.Token

	accountId, salt, parameters, err := ba.stores.passphraseRegistrationToken.Validate(token)
	if err != nil {
		return "", err
	}

	requestPayloadBytes, err := json.Marshal(request.Payload)
	if err != nil {
		return "", err
	}

	if err := ba.crypto.passphraseVerification.Verify(
		request.Signature,
		request.Payload.PassphraseAuthentication.PublicKey,
		requestPayloadBytes,
	); err != nil {
		return "", err
	}

	passphraseAuthenticationKeyDigest := ba.crypto.digest.Sum([]byte(request.Payload.PassphraseAuthentication.PublicKey))
	if err := ba.stores.passphraseAuthenticationKey.Commit(
		accountId,
		passphraseAuthenticationKeyDigest,
		salt,
		parameters,
	); err != nil {
		return "", err
	}

	ba.stores.passphraseRegistrationToken.Invalidate(token)

	publicKey, err := ba.crypto.keyPairs.response.Public()
	if err != nil {
		return "", err
	}

	publicKeyDigest := ba.crypto.digest.Sum([]byte(publicKey))

	payload := messages.RegisterPassphraseAuthenticationKeyResponsePayload{
		Identification: messages.RegisterPassphraseAuthenticationKeyResponseIdentification{
			AccountId: accountId,
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

	message := messages.RegisterPassphraseAuthenticationKeyResponse{
		Payload:   payload,
		Signature: signature,
	}

	bytes, err := json.Marshal(message)
	if err != nil {
		return "", err
	}

	return string(bytes), nil
}
