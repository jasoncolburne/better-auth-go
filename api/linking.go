package api

import (
	"fmt"

	"github.com/jasoncolburne/better-auth-go/pkg/messages"
)

func (ba *BetterAuthServer[AttributesType]) LinkDevice(message string) (string, error) {
	request, err := messages.ParseLinkDeviceRequest(message)
	if err != nil {
		return "", err
	}

	if err := request.Verify(ba.crypto.Verifier, request.Payload.Request.Authentication.PublicKey); err != nil {
		return "", err
	}

	linkContainer := messages.NewLinkContainer(
		request.Payload.Request.Link.Payload,
		request.Payload.Request.Link.Signature,
	)

	if err := linkContainer.Verify(
		ba.crypto.Verifier,
		linkContainer.Payload.Authentication.PublicKey,
	); err != nil {
		return "", err
	}

	if linkContainer.Payload.Authentication.Identity != request.Payload.Request.Authentication.Identity {
		return "", fmt.Errorf("mismatched identities")
	}

	ba.store.Authentication.Key.Rotate(
		request.Payload.Request.Authentication.Identity,
		request.Payload.Request.Authentication.Device,
		request.Payload.Request.Authentication.PublicKey,
		request.Payload.Request.Authentication.RotationHash,
	)

	if err := ba.store.Authentication.Key.Register(
		linkContainer.Payload.Authentication.Identity,
		linkContainer.Payload.Authentication.Device,
		linkContainer.Payload.Authentication.PublicKey,
		linkContainer.Payload.Authentication.RotationHash,
		true,
	); err != nil {
		return "", err
	}

	responseKeyHash, err := ba.responseKeyHash()
	if err != nil {
		return "", err
	}

	response := messages.NewLinkDeviceResponse(
		messages.LinkDeviceResponsePayload{},
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

func (ba *BetterAuthServer[AttributesType]) UnlinkDevice(message string) (string, error) {
	request, err := messages.ParseUnlinkDeviceRequest(message)
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

	if err := ba.store.Authentication.Key.RevokeDevice(
		request.Payload.Request.Authentication.Identity,
		request.Payload.Request.Link.Device,
	); err != nil {
		return "", err
	}

	responseKeyHash, err := ba.responseKeyHash()
	if err != nil {
		return "", err
	}

	response := messages.NewUnlinkDeviceResponse(
		messages.UnlinkDeviceResponsePayload{},
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
