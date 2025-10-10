package api

import (
	"fmt"

	"github.com/jasoncolburne/better-auth-go/pkg/messages"
)

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

	device := ba.crypto.Hasher.Sum([]byte(request.Payload.Request.Authentication.PublicKey + request.Payload.Request.Authentication.RotationHash))

	if device != request.Payload.Request.Authentication.Device {
		return "", fmt.Errorf("bad device derivation")
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

func (ba *BetterAuthServer[AttributesType]) RecoverAccount(message string) (string, error) {
	request, err := messages.ParseRecoverAccountRequest(message)
	if err != nil {
		return "", err
	}

	if err := request.Verify(ba.crypto.Verifier, request.Payload.Request.Authentication.RecoveryKey); err != nil {
		return "", err
	}

	device := ba.crypto.Hasher.Sum([]byte(request.Payload.Request.Authentication.PublicKey + request.Payload.Request.Authentication.RotationHash))
	if device != request.Payload.Request.Authentication.Device {
		return "", fmt.Errorf("bad device derivation")
	}

	hash := ba.crypto.Hasher.Sum([]byte(request.Payload.Request.Authentication.RecoveryKey))
	if err := ba.store.Recovery.Hash.Rotate(
		request.Payload.Request.Authentication.Identity,
		hash,
		request.Payload.Request.Authentication.RecoveryHash,
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

	serverIdentity, err := ba.crypto.KeyPair.Response.Identity()
	if err != nil {
		return "", err
	}

	response := messages.NewRecoverAccountResponse(
		messages.RecoverAccountResponsePayload{},
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

func (ba *BetterAuthServer[AttributesType]) DeleteAccount(message string) (string, error) {
	request, err := messages.ParseDeleteAccountRequest(message)
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
		request.Payload.Request.Authentication.RotationHash,
	); err != nil {
		return "", err
	}

	if err := ba.store.Authentication.Key.DeleteIdentity(
		request.Payload.Request.Authentication.Identity,
	); err != nil {
		return "", err
	}

	serverIdentity, err := ba.crypto.KeyPair.Response.Identity()
	if err != nil {
		return "", err
	}

	response := messages.NewDeleteAccountResponse(
		messages.DeleteAccountResponsePayload{},
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
