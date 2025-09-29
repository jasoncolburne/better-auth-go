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
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	serverResponsePublicKey, err := serverResponseKey.Public()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	serverAccessKey, err := crypto.NewSecp256r1()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

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
			PublicKey: serverAccessKey,
			Verifier:  verifier,
		},
		&api.VerifierEncodingContainer{
			TokenEncoder: tokenEncoder,
			Timestamper:  timestamper,
		},
		&api.VerifierStoreContainer{
			AccessNonce: accessNonceStore,
		},
	)

	currentAuthenticationKey, err := crypto.NewSecp256r1()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	nextAuthenticationKey, err := crypto.NewSecp256r1()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	nextNextAuthenticationKey, err := crypto.NewSecp256r1()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	recoveryKey, err := crypto.NewSecp256r1()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	nextAuthenticationPublicKey, err := nextAuthenticationKey.Public()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	nextNextAuthenticationPublicKey, err := nextNextAuthenticationKey.Public()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	rotationHash := hasher.Sum([]byte(nextAuthenticationPublicKey))
	currentKey, err := currentAuthenticationKey.Public()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	recoveryPublicKey, err := recoveryKey.Public()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	recoveryHash := hasher.Sum([]byte(recoveryPublicKey))

	device := hasher.Sum([]byte(currentKey))
	identitySeed := fmt.Sprintf("%s%s%s", currentKey, rotationHash, recoveryHash)
	identity := hasher.Sum([]byte(identitySeed))

	nonce, err := noncer.Generate128()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
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
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	message, err := createRequest.Serialize()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	reply, err := ba.CreateAccount(message)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	createResponse, err := messages.ParseCreateAccountResponse(reply)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	if err := createResponse.Verify(serverResponseKey.Verifier(), serverResponsePublicKey); err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	if !strings.EqualFold(nonce, createResponse.Payload.Access.Nonce) {
		fmt.Printf("bad nonce 1")
		t.Fail()
	}

	nonce, err = noncer.Generate128()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
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
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	message, err = rotateRequest.Serialize()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	reply, err = ba.RotateAuthenticationKey(message)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	rotateResponse, err := messages.ParseRotateAuthenticationKeyResponse(reply)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	if err := rotateResponse.Verify(serverResponseKey.Verifier(), serverResponsePublicKey); err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	if !strings.EqualFold(nonce, rotateResponse.Payload.Access.Nonce) {
		fmt.Printf("bad nonce 2")
		t.Fail()
	}

	nonce, err = noncer.Generate128()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
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
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	reply, err = ba.StartAuthentication(message)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	startAuthenticationResponse, err := messages.ParseStartAuthenticationResponse(reply)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	if err := startAuthenticationResponse.Verify(serverResponseKey.Verifier(), serverResponsePublicKey); err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	if !strings.EqualFold(nonce, startAuthenticationResponse.Payload.Access.Nonce) {
		fmt.Printf("bad nonce 3")
		t.Fail()
	}

	nonce, err = noncer.Generate128()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	clientAccessKey, err := crypto.NewSecp256r1()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	clientNextAccessKey, err := crypto.NewSecp256r1()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	clientNextNextAccessKey, err := crypto.NewSecp256r1()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	clientAccessPublicKey, err := clientAccessKey.Public()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	clientNextAccessPublicKey, err := clientNextAccessKey.Public()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	clientNextNextAccessPublicKey, err := clientNextNextAccessKey.Public()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
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
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	message, err = finishAuthenticationRequest.Serialize()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
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
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	finishAuthenticationResponse, err := messages.ParseFinishAuthenticationResponse(reply)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	if err := finishAuthenticationResponse.Verify(serverResponseKey.Verifier(), serverResponsePublicKey); err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	if !strings.EqualFold(nonce, finishAuthenticationRequest.Payload.Access.Nonce) {
		fmt.Printf("bad nonce")
		t.Fail()
	}

	nonce, err = noncer.Generate128()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
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
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	message, err = refreshAccessTokenRequest.Serialize()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	reply, err = ba.RefreshAccessToken(message)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	refreshAccessTokenResponse, err := messages.ParseRefreshAccessTokenResponse(reply)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	if err := refreshAccessTokenResponse.Verify(serverResponseKey.Verifier(), serverResponsePublicKey); err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	if !strings.EqualFold(nonce, refreshAccessTokenResponse.Payload.Access.Nonce) {
		fmt.Printf("bad nonce")
		t.Fail()
	}

	nonce, err = noncer.Generate128()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
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
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	message, err = accessRequest.Serialize()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	verifiedIdentity, verifiedAttributes, err := av.Verify(message, &MockAttributes{})
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	if !strings.EqualFold(verifiedIdentity, identity) {
		fmt.Printf("incorrect identity verified")
		t.Fail()
	}

	if !slices.Equal(attributes.PermissionsByRole["admin"], verifiedAttributes.PermissionsByRole["admin"]) {
		fmt.Printf("attribute mismatch")
	}

	recoveredAuthenticationKey, err := crypto.NewSecp256r1()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	recoveredNextAuthenticationKey, err := crypto.NewSecp256r1()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	recoveredAuthenticationPublicKey, err := recoveredAuthenticationKey.Public()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	recoveredNextAuthenticationPublicKey, err := recoveredNextAuthenticationKey.Public()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	recoveredDevice := hasher.Sum([]byte(recoveredAuthenticationPublicKey))
	rotationHash = hasher.Sum([]byte(recoveredNextAuthenticationPublicKey))

	nonce, err = noncer.Generate128()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	recoverRequest := messages.NewRecoverAccountRequest(
		messages.RecoverAccountRequestPayload{
			Authentication: messages.RecoverAccountRequestAuthentication{
				Device:       recoveredDevice,
				Identity:     identity,
				PublicKey:    recoveredAuthenticationPublicKey,
				RecoveryKey:  recoveryPublicKey,
				RotationHash: rotationHash,
			},
		},
		nonce,
	)

	if err := recoverRequest.Sign(recoveryKey); err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	message, err = recoverRequest.Serialize()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	reply, err = ba.RecoverAccount(message)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	recoverAccountResponse, err := messages.ParseRecoverAccountResponse(reply)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	if err := recoverAccountResponse.Verify(serverResponseKey.Verifier(), serverResponsePublicKey); err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	if !strings.EqualFold(nonce, recoverAccountResponse.Payload.Access.Nonce) {
		fmt.Printf("bad nonce")
		t.Fail()
	}

	linkedAuthenticationKey, err := crypto.NewSecp256r1()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	linkedNextAuthenticationKey, err := crypto.NewSecp256r1()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	linkedAuthenticationPublicKey, err := linkedAuthenticationKey.Public()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	linkedNextAuthenticationPublicKey, err := linkedNextAuthenticationKey.Public()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	linkedDevice := hasher.Sum([]byte(linkedAuthenticationPublicKey))
	rotationHash = hasher.Sum([]byte(linkedNextAuthenticationPublicKey))

	nonce, err = noncer.Generate128()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
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
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	linkDeviceRequest := messages.NewLinkDeviceRequest(
		messages.LinkDeviceRequestPayload{
			Authentication: messages.LinkDeviceRequestAuthentication{
				Device:   recoveredDevice,
				Identity: identity,
			},
			Link: *linkContainer,
		},
		nonce,
	)

	if err := linkDeviceRequest.Sign(recoveredAuthenticationKey); err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	message, err = linkDeviceRequest.Serialize()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	reply, err = ba.LinkDevice(message)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	linkDeviceResponse, err := messages.ParseLinkDeviceResponse(reply)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	if err := linkDeviceResponse.Verify(serverResponseKey.Verifier(), serverResponsePublicKey); err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	if !strings.EqualFold(nonce, linkDeviceResponse.Payload.Access.Nonce) {
		fmt.Printf("bad nonce")
		t.Fail()
	}
}
