package api_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jasoncolburne/better-auth-go/api"
	"github.com/jasoncolburne/better-auth-go/examples/crypto"
	"github.com/jasoncolburne/better-auth-go/examples/encoding"
	"github.com/jasoncolburne/better-auth-go/examples/storage"
	"github.com/jasoncolburne/better-auth-go/pkg/encodinginterfaces"
	"github.com/jasoncolburne/better-auth-go/pkg/messages"
)

type MockAttributes struct {
	PermissionsByRole map[string][]string `json:"permissionsByRole"`
}

type FakeAccessRequest = messages.AccessRequest[FakeAccessRequestPayload, MockAttributes]

type FakeAccessRequestPayload struct {
	Foo string `json:"foo"`
	Bar string `json:"bar"`
}

func NewFakeAccessRequest(
	payload FakeAccessRequestPayload,
	timestamper encodinginterfaces.Timestamper,
	token string,
	nonce string,
) *FakeAccessRequest {
	return messages.NewAccessRequest[FakeAccessRequestPayload, MockAttributes, FakeAccessRequest](
		payload,
		timestamper,
		token,
		nonce,
	)
}

func TestAccess(t *testing.T) {
	if err := testFlow(); err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}
}

func testFlow() error {
	accessLifetime := 15 * time.Minute
	accessWindow := 30 * time.Second
	refreshLifetime := 12 * time.Hour
	authenticationChallengeLifetime := 1 * time.Minute

	hasher := crypto.NewBlake3()
	verifier := crypto.NewSecp256r1Verifier()
	noncer := crypto.NewNoncer()

	accessKeyHashStore := storage.NewInMemoryTimeLockStore(refreshLifetime)
	accessNonceStore := storage.NewInMemoryTimeLockStore(accessWindow)
	authenticationKeyStore := storage.NewInMemoryAuthenticationKeyStore(hasher)
	authenticationNonceStore := storage.NewInMemoryAuthenticationNonceStore(authenticationChallengeLifetime)
	recoveryHashStore := storage.NewInMemoryRecoveryHashStore()

	identityVerifier := encoding.NewMockIdentityVerifier(hasher)
	timestamper := encoding.NewRfc3339Nano()
	tokenEncoder := encoding.NewTokenEncoder[MockAttributes]()

	serverResponseKey, err := crypto.NewSecp256r1()
	if err != nil {
		return err
	}

	serverResponsePublicKey, err := serverResponseKey.Public()
	if err != nil {
		return err
	}

	serverAccessKey, err := crypto.NewSecp256r1()
	if err != nil {
		return err
	}

	accessIdentity, err := serverAccessKey.Identity()
	if err != nil {
		return err
	}

	accessKeyStore := storage.NewVerificationKeyStore()
	accessKeyStore.Add(accessIdentity, serverAccessKey)

	ba := api.NewBetterAuthServer[MockAttributes](
		&api.CryptoContainer{
			Hasher: hasher,
			KeyPair: &api.KeyPairContainer{
				Access:   serverAccessKey,
				Response: serverResponseKey,
			},
			Noncer:   noncer,
			Verifier: verifier,
		},
		&api.EncodingContainer{
			IdentityVerifier: identityVerifier,
			Timestamper:      timestamper,
			TokenEncoder:     tokenEncoder,
		},
		&api.ExpiryContainer{
			Access:  accessLifetime,
			Refresh: refreshLifetime,
		},
		&api.StoresContainer{
			Access: &api.AccessStoreContainer{
				KeyHash: accessKeyHashStore,
			},
			Authentication: &api.AuthenticationStoreContainer{
				Key:   authenticationKeyStore,
				Nonce: authenticationNonceStore,
			},
			Recovery: &api.RecoveryStoreContainer{
				Hash: recoveryHashStore,
			},
		},
	)

	av := api.NewAccessVerifier[MockAttributes](
		&api.VerifierCryptoContainer{
			Verifier: verifier,
		},
		&api.VerifierEncodingContainer{
			TokenEncoder: tokenEncoder,
			Timestamper:  timestamper,
		},
		&api.VerifierStoreContainer{
			AccessNonce: accessNonceStore,
			AccessKey:   accessKeyStore,
		},
	)

	currentAuthenticationKey, err := crypto.NewSecp256r1()
	if err != nil {
		return err
	}

	nextAuthenticationKey, err := crypto.NewSecp256r1()
	if err != nil {
		return err
	}

	nextNextAuthenticationKey, err := crypto.NewSecp256r1()
	if err != nil {
		return err
	}

	recoveryKey, err := crypto.NewSecp256r1()
	if err != nil {
		return err
	}

	nextAuthenticationPublicKey, err := nextAuthenticationKey.Public()
	if err != nil {
		return err
	}

	nextNextAuthenticationPublicKey, err := nextNextAuthenticationKey.Public()
	if err != nil {
		return err
	}

	rotationHash := hasher.Sum([]byte(nextAuthenticationPublicKey))
	currentKey, err := currentAuthenticationKey.Public()
	if err != nil {
		return err
	}

	recoveryPublicKey, err := recoveryKey.Public()
	if err != nil {
		return err
	}

	recoveryHash := hasher.Sum([]byte(recoveryPublicKey))

	device := hasher.Sum([]byte(currentKey))
	identitySeed := fmt.Sprintf("%s%s%s", currentKey, rotationHash, recoveryHash)
	identity := hasher.Sum([]byte(identitySeed))

	nonce, err := noncer.Generate128()
	if err != nil {
		return err
	}

	createRequest := messages.NewCreateAccountRequest(
		messages.CreateAccountRequestPayload{
			Authentication: messages.CreateAccountRequestAuthentication{
				Device:       device,
				Identity:     identity,
				PublicKey:    currentKey,
				RecoveryHash: recoveryHash,
				RotationHash: rotationHash,
			},
		},
		nonce,
	)

	if err := createRequest.Sign(currentAuthenticationKey); err != nil {
		return err
	}

	message, err := createRequest.Serialize()
	if err != nil {
		return err
	}

	reply, err := ba.CreateAccount(message)
	if err != nil {
		return err
	}

	createResponse, err := messages.ParseCreateAccountResponse(reply)
	if err != nil {
		return err
	}

	if err := createResponse.Verify(serverResponseKey.Verifier(), serverResponsePublicKey); err != nil {
		return err
	}

	if !strings.EqualFold(nonce, createResponse.Payload.Access.Nonce) {
		return fmt.Errorf("bad nonce 1")
	}

	nonce, err = noncer.Generate128()
	if err != nil {
		return err
	}

	rotationHash = hasher.Sum([]byte(nextNextAuthenticationPublicKey))

	rotateRequest := messages.NewRotateAuthenticationKeyRequest(
		messages.RotateAuthenticationKeyRequestPayload{
			Authentication: messages.RotateAuthenticationKeyRequestAuthentication{
				Device:       device,
				Identity:     identity,
				PublicKey:    nextAuthenticationPublicKey,
				RotationHash: rotationHash,
			},
		},
		nonce,
	)

	if err := rotateRequest.Sign(nextAuthenticationKey); err != nil {
		return err
	}

	message, err = rotateRequest.Serialize()
	if err != nil {
		return err
	}

	reply, err = ba.RotateAuthenticationKey(message)
	if err != nil {
		return err
	}

	rotateResponse, err := messages.ParseRotateAuthenticationKeyResponse(reply)
	if err != nil {
		return err
	}

	if err := rotateResponse.Verify(serverResponseKey.Verifier(), serverResponsePublicKey); err != nil {
		return err
	}

	if !strings.EqualFold(nonce, rotateResponse.Payload.Access.Nonce) {
		return fmt.Errorf("bad nonce 2")
	}

	nonce, err = noncer.Generate128()
	if err != nil {
		return err
	}

	startAuthenticationRequest := messages.NewStartAuthenticationRequest(
		messages.StartAuthenticationRequestPayload{
			Authentication: messages.StartAuthenticationRequestAuthentication{
				Identity: identity,
			},
		},
		nonce,
	)

	message, err = startAuthenticationRequest.Serialize()
	if err != nil {
		return err
	}

	reply, err = ba.StartAuthentication(message)
	if err != nil {
		return err
	}

	startAuthenticationResponse, err := messages.ParseStartAuthenticationResponse(reply)
	if err != nil {
		return err
	}

	if err := startAuthenticationResponse.Verify(serverResponseKey.Verifier(), serverResponsePublicKey); err != nil {
		return err
	}

	if !strings.EqualFold(nonce, startAuthenticationResponse.Payload.Access.Nonce) {
		return fmt.Errorf("bad nonce 3")
	}

	nonce, err = noncer.Generate128()
	if err != nil {
		return err
	}

	clientAccessKey, err := crypto.NewSecp256r1()
	if err != nil {
		return err
	}

	clientNextAccessKey, err := crypto.NewSecp256r1()
	if err != nil {
		return err
	}

	clientNextNextAccessKey, err := crypto.NewSecp256r1()
	if err != nil {
		return err
	}

	clientAccessPublicKey, err := clientAccessKey.Public()
	if err != nil {
		return err
	}

	clientNextAccessPublicKey, err := clientNextAccessKey.Public()
	if err != nil {
		return err
	}

	clientNextNextAccessPublicKey, err := clientNextNextAccessKey.Public()
	if err != nil {
		return err
	}

	rotationHash = hasher.Sum([]byte(clientNextAccessPublicKey))

	finishAuthenticationRequest := messages.NewFinishAuthenticationRequest(
		messages.FinishAuthenticationRequestPayload{
			Access: messages.FinishAuthenticationRequestAccess{
				PublicKey:    clientAccessPublicKey,
				RotationHash: rotationHash,
			},
			Authentication: messages.FinishAuthenticationRequestAuthentication{
				Device: device,
				Nonce:  startAuthenticationResponse.Payload.Response.Authentication.Nonce,
			},
		},
		nonce,
	)

	if err := finishAuthenticationRequest.Sign(nextAuthenticationKey); err != nil {
		return err
	}

	message, err = finishAuthenticationRequest.Serialize()
	if err != nil {
		return err
	}

	attributes := MockAttributes{
		PermissionsByRole: map[string][]string{
			"admin": {"read", "write"},
		},
	}

	reply, err = ba.FinishAuthentication(
		message,
		attributes,
	)
	if err != nil {
		return err
	}

	finishAuthenticationResponse, err := messages.ParseFinishAuthenticationResponse(reply)
	if err != nil {
		return err
	}

	if err := finishAuthenticationResponse.Verify(serverResponseKey.Verifier(), serverResponsePublicKey); err != nil {
		return err
	}

	if !strings.EqualFold(nonce, finishAuthenticationRequest.Payload.Access.Nonce) {
		return fmt.Errorf("bad nonce")
	}

	nonce, err = noncer.Generate128()
	if err != nil {
		return err
	}

	rotationHash = hasher.Sum([]byte(clientNextNextAccessPublicKey))

	refreshAccessTokenRequest := messages.NewRefreshAccessTokenRequest(
		messages.RefreshAccessTokenRequestPayload{
			Access: messages.RefreshAccessTokenRequestAccess{
				PublicKey:    clientNextAccessPublicKey,
				RotationHash: rotationHash,
				Token:        finishAuthenticationResponse.Payload.Response.Access.Token,
			},
		},
		nonce,
	)

	if err := refreshAccessTokenRequest.Sign(clientNextAccessKey); err != nil {
		return err
	}

	message, err = refreshAccessTokenRequest.Serialize()
	if err != nil {
		return err
	}

	reply, err = ba.RefreshAccessToken(message)
	if err != nil {
		return err
	}

	refreshAccessTokenResponse, err := messages.ParseRefreshAccessTokenResponse(reply)
	if err != nil {
		return err
	}

	if err := refreshAccessTokenResponse.Verify(serverResponseKey.Verifier(), serverResponsePublicKey); err != nil {
		return err
	}

	if !strings.EqualFold(nonce, refreshAccessTokenResponse.Payload.Access.Nonce) {
		return fmt.Errorf("bad nonce")
	}

	nonce, err = noncer.Generate128()
	if err != nil {
		return err
	}

	accessRequest := NewFakeAccessRequest(
		FakeAccessRequestPayload{
			Foo: "bar",
			Bar: "foo",
		},
		timestamper,
		refreshAccessTokenResponse.Payload.Response.Access.Token,
		nonce,
	)

	if err := accessRequest.Sign(clientNextAccessKey); err != nil {
		return err
	}

	message, err = accessRequest.Serialize()
	if err != nil {
		return err
	}

	verifiedIdentity, verifiedAttributes, err := av.Verify(message, &MockAttributes{})
	if err != nil {
		return err
	}

	if !strings.EqualFold(verifiedIdentity, identity) {
		return fmt.Errorf("incorrect identity verified")
	}

	if !slices.Equal(attributes.PermissionsByRole["admin"], verifiedAttributes.PermissionsByRole["admin"]) {
		return fmt.Errorf("attribute mismatch")
	}

	recoveredAuthenticationKey, err := crypto.NewSecp256r1()
	if err != nil {
		return err
	}

	recoveredNextAuthenticationKey, err := crypto.NewSecp256r1()
	if err != nil {
		return err
	}

	nextRecoveryKey, err := crypto.NewSecp256r1()
	if err != nil {
		return err
	}

	recoveredAuthenticationPublicKey, err := recoveredAuthenticationKey.Public()
	if err != nil {
		return err
	}

	recoveredNextAuthenticationPublicKey, err := recoveredNextAuthenticationKey.Public()
	if err != nil {
		return err
	}

	nextRecoveryPublicKey, err := nextRecoveryKey.Public()
	if err != nil {
		return err
	}

	recoveredDevice := hasher.Sum([]byte(recoveredAuthenticationPublicKey))
	rotationHash = hasher.Sum([]byte(recoveredNextAuthenticationPublicKey))
	nextRecoveryHash := hasher.Sum([]byte(nextRecoveryPublicKey))

	nonce, err = noncer.Generate128()
	if err != nil {
		return err
	}

	recoverRequest := messages.NewRecoverAccountRequest(
		messages.RecoverAccountRequestPayload{
			Authentication: messages.RecoverAccountRequestAuthentication{
				Device:       recoveredDevice,
				Identity:     identity,
				PublicKey:    recoveredAuthenticationPublicKey,
				RecoveryHash: nextRecoveryHash,
				RecoveryKey:  recoveryPublicKey,
				RotationHash: rotationHash,
			},
		},
		nonce,
	)

	if err := recoverRequest.Sign(recoveryKey); err != nil {
		return err
	}

	message, err = recoverRequest.Serialize()
	if err != nil {
		return err
	}

	reply, err = ba.RecoverAccount(message)
	if err != nil {
		return err
	}

	recoverAccountResponse, err := messages.ParseRecoverAccountResponse(reply)
	if err != nil {
		return err
	}

	if err := recoverAccountResponse.Verify(serverResponseKey.Verifier(), serverResponsePublicKey); err != nil {
		return err
	}

	if !strings.EqualFold(nonce, recoverAccountResponse.Payload.Access.Nonce) {
		return fmt.Errorf("bad nonce")
	}

	linkedAuthenticationKey, err := crypto.NewSecp256r1()
	if err != nil {
		return err
	}

	linkedNextAuthenticationKey, err := crypto.NewSecp256r1()
	if err != nil {
		return err
	}

	linkedAuthenticationPublicKey, err := linkedAuthenticationKey.Public()
	if err != nil {
		return err
	}

	linkedNextAuthenticationPublicKey, err := linkedNextAuthenticationKey.Public()
	if err != nil {
		return err
	}

	linkedDevice := hasher.Sum([]byte(linkedAuthenticationPublicKey))
	rotationHash = hasher.Sum([]byte(linkedNextAuthenticationPublicKey))

	nonce, err = noncer.Generate128()
	if err != nil {
		return err
	}

	linkContainer := messages.NewLinkContainer(
		messages.LinkContainerPayload{
			Authentication: messages.LinkContainerAuthentication{
				Device:       linkedDevice,
				Identity:     identity,
				PublicKey:    linkedAuthenticationPublicKey,
				RotationHash: rotationHash,
			},
		},
		nil,
	)

	if err := linkContainer.Sign(linkedAuthenticationKey); err != nil {
		return err
	}

	recoveredNextNextAuthenticationKey, err := crypto.NewSecp256r1()
	if err != nil {
		return err
	}

	recoveredNextNextAuthenticationPublicKey, err := recoveredNextNextAuthenticationKey.Public()
	if err != nil {
		return err
	}

	recoveredNextRotationHash := hasher.Sum([]byte(recoveredNextNextAuthenticationPublicKey))

	linkDeviceRequest := messages.NewLinkDeviceRequest(
		messages.LinkDeviceRequestPayload{
			Authentication: messages.LinkDeviceRequestAuthentication{
				Device:       recoveredDevice,
				Identity:     identity,
				PublicKey:    recoveredNextAuthenticationPublicKey,
				RotationHash: recoveredNextRotationHash,
			},
			Link: *linkContainer,
		},
		nonce,
	)

	if err := linkDeviceRequest.Sign(recoveredNextAuthenticationKey); err != nil {
		return err
	}

	message, err = linkDeviceRequest.Serialize()
	if err != nil {
		return err
	}

	reply, err = ba.LinkDevice(message)
	if err != nil {
		return err
	}

	linkDeviceResponse, err := messages.ParseLinkDeviceResponse(reply)
	if err != nil {
		return err
	}

	if err := linkDeviceResponse.Verify(serverResponseKey.Verifier(), serverResponsePublicKey); err != nil {
		return err
	}

	if !strings.EqualFold(nonce, linkDeviceResponse.Payload.Access.Nonce) {
		return fmt.Errorf("bad nonce")
	}

	return nil
}
