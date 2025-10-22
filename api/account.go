package api

import (
	"context"
	"fmt"

	"github.com/jasoncolburne/better-auth-go/pkg/messages"
)

func (ba *BetterAuthServer[AttributesType]) CreateAccount(ctx context.Context, message string) (string, error) {
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
		ctx,
		identity,
		request.Payload.Request.Authentication.RecoveryHash,
	); err != nil {
		return "", err
	}

	if err := ba.store.Authentication.Key.Register(
		ctx,
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

func (ba *BetterAuthServer[AttributesType]) RecoverAccount(ctx context.Context, message string) (string, error) {
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
		ctx,
		request.Payload.Request.Authentication.Identity,
		hash,
		request.Payload.Request.Authentication.RecoveryHash,
	); err != nil {
		return "", err
	}

	if err := ba.store.Authentication.Key.RevokeDevices(
		ctx,
		request.Payload.Request.Authentication.Identity,
	); err != nil {
		return "", err
	}

	if err := ba.store.Authentication.Key.Register(
		ctx,
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

func (ba *BetterAuthServer[AttributesType]) DeleteAccount(ctx context.Context, message string) (string, error) {
	request, err := messages.ParseDeleteAccountRequest(message)
	if err != nil {
		return "", err
	}

	if err := request.Verify(ba.crypto.Verifier, request.Payload.Request.Authentication.PublicKey); err != nil {
		return "", err
	}

	if err := ba.store.Authentication.Key.Rotate(
		ctx,
		request.Payload.Request.Authentication.Identity,
		request.Payload.Request.Authentication.Device,
		request.Payload.Request.Authentication.PublicKey,
		request.Payload.Request.Authentication.RotationHash,
	); err != nil {
		return "", err
	}

	if err := ba.store.Authentication.Key.DeleteIdentity(
		ctx,
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

func (ba *BetterAuthServer[AttributesType]) ChangeRecoveryKey(ctx context.Context, message string) (string, error) {
	request, err := messages.ParseChangeRecoveryKeyRequest(message)
	if err != nil {
		return "", err
	}

	if err := request.Verify(ba.crypto.Verifier, request.Payload.Request.Authentication.PublicKey); err != nil {
		return "", err
	}

	if err := ba.store.Authentication.Key.Rotate(
		ctx,
		request.Payload.Request.Authentication.Identity,
		request.Payload.Request.Authentication.Device,
		request.Payload.Request.Authentication.PublicKey,
		request.Payload.Request.Authentication.RotationHash,
	); err != nil {
		return "", err
	}

	if err := ba.store.Recovery.Hash.Change(
		ctx,
		request.Payload.Request.Authentication.Identity,
		request.Payload.Request.Authentication.RecoveryHash,
	); err != nil {
		return "", err
	}

	serverIdentity, err := ba.crypto.KeyPair.Response.Identity()
	if err != nil {
		return "", err
	}

	// this is replayable, and should be fixed but making it not fixed
	response := messages.NewChangeRecoveryKeyResponse(
		messages.ChangeRecoveryKeyResponsePayload{},
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
