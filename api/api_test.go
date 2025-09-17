package api_test

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/jasoncolburne/better-auth-go/api"
	"github.com/jasoncolburne/better-auth-go/examples/cesrgolite"
	"github.com/jasoncolburne/better-auth-go/examples/storage"
	"github.com/jasoncolburne/better-auth-go/pkg/messages"
)

type FakeAccessRequest struct {
	Token     string `json:"token"`
	Payload   FakeAccessRequestPayload
	Signature string `json:"signature"`
}

type FakeAccessRequestPayload struct {
	Access  messages.Access          `json:"access"`
	Request FakeAccessRequestRequest `json:"request"`
}

type FakeAccessRequestRequest struct {
	Label string `json:"label"`
}

func TestAccess(t *testing.T) {
	digester := cesrgolite.NewBlake3()
	verifier := cesrgolite.NewSecp256r1Verifier()
	salter := cesrgolite.NewSalter()

	accessNonceStore := storage.NewInMemoryAccessNonceStore()
	authenticationKeyStore := storage.NewInMemoryAuthenticationKeyStore(digester)
	authenticationNonceStore := storage.NewInMemoryAuthenticationNonceStore()
	refreshKeyStore := storage.NewInMemoryRefreshKeyStore(digester)
	refreshNonceStore := storage.NewInMemoryRefreshNonceStore(digester)
	registrationTokenStore := storage.NewInMemoryRegistrationTokenStore()

	serverResponseKey, err := cesrgolite.NewSecp256r1()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	serverAccessKey, err := cesrgolite.NewSecp256r1()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	ba := api.NewBetterAuth(
		authenticationNonceStore,
		authenticationKeyStore,
		nil,
		nil,
		refreshNonceStore,
		refreshKeyStore,
		registrationTokenStore,
		digester,
		nil,
		nil,
		verifier,
		serverAccessKey,
		serverResponseKey,
	)

	generateResponseString, err := ba.GenerateRegistrationMaterials()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	generateResponse := &messages.RegistrationMaterials{}
	if err := json.Unmarshal([]byte(generateResponseString), generateResponse); err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	registrationToken := generateResponse.Payload.Registration.Token

	entropy := [32]byte{}
	_, err = rand.Read(entropy[:])
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	deviceId := digester.Sum(entropy[:])
	currentAuthenticationKey, err := cesrgolite.NewSecp256r1()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	nextAuthenticationKey, err := cesrgolite.NewSecp256r1()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	nextKey, err := nextAuthenticationKey.Public()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	nextAuthenticationPublicKeyDigest := digester.Sum([]byte(nextKey))
	currentAuthenticationPublicKey, err := currentAuthenticationKey.Public()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	registrationPayload := messages.RegisterAuthenticationKeyRequestPayload{
		Registration: messages.RegisterAuthenticationKeyRequestRegistration{
			Token: registrationToken,
		},
		Identification: messages.RegisterAuthenticationKeyRequestIdentification{
			DeviceId: deviceId,
		},
		Authentication: messages.RegisterAuthenticationKeyRequestAuthentication{
			PublicKeys: messages.PublicKeys{
				Current:    currentAuthenticationPublicKey,
				NextDigest: nextAuthenticationPublicKeyDigest,
			},
		},
	}

	payloadJson, err := json.Marshal(registrationPayload)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	signature, err := currentAuthenticationKey.Sign(payloadJson)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	registrationRequest := &messages.RegisterAuthenticationKeyRequest{
		Payload:   registrationPayload,
		Signature: signature,
	}

	response, err := ba.RegisterAuthenticationKey(registrationRequest)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	registrationResponse := &messages.RegisterAuthenticationKeyResponse{}
	err = json.Unmarshal([]byte(response), registrationResponse)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	accountId := registrationResponse.Payload.Identification.AccountId
	beginAuthenticationRequest := &messages.BeginAuthenticationRequest{
		Payload: messages.BeginAuthenticationRequestPayload{
			Identification: messages.BeginAuthenticationRequestIdentification{
				AccountId: accountId,
			},
		},
	}

	response, err = ba.BeginAuthentication(beginAuthenticationRequest)

	beginAuthenticationResponse := &messages.BeginAuthenticationResponse{}
	err = json.Unmarshal([]byte(response), beginAuthenticationResponse)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	refreshKey, err := cesrgolite.NewSecp256r1()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	refreshPublicKey, err := refreshKey.Public()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	nextRefreshNonce, err := salter.Generate128()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}
	nextRefreshNonceDigest := digester.Sum([]byte(nextRefreshNonce))

	completeAuthenticationRequestPayload := messages.CompleteAuthenticationRequestPayload{
		Identification: messages.CompleteAuthenticationRequestIdentification{
			DeviceId: deviceId,
		},
		Authentication: messages.CompleteAuthenticationRequestAuthentication{
			Nonce: beginAuthenticationResponse.Payload.Authentication.Nonce,
		},
		Refresh: messages.CompleteAuthenticationRequestRefresh{
			PublicKey: refreshPublicKey,
			Nonces: messages.Nonces{
				NextDigest: nextRefreshNonceDigest,
			},
		},
	}

	payloadJson, err = json.Marshal(completeAuthenticationRequestPayload)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	signature, err = currentAuthenticationKey.Sign(payloadJson)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	completeAuthenticationRequest := &messages.CompleteAuthenticationRequest{
		Payload:   completeAuthenticationRequestPayload,
		Signature: signature,
	}

	response, err = ba.CompleteAuthentication(completeAuthenticationRequest)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	completeAuthenticationResponse := &messages.CompleteAuthenticationResponse{}
	if err := json.Unmarshal([]byte(response), completeAuthenticationResponse); err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	sessionId := completeAuthenticationResponse.Payload.Refresh.SessionId
	currentRefreshNonce := nextRefreshNonce
	nextRefreshNonce, err = salter.Generate128()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}
	nextRefreshNonceDigest = digester.Sum([]byte(nextRefreshNonce))

	accessKey, err := cesrgolite.NewSecp256r1()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	accessPublicKey, err := accessKey.Public()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	refreshAccessTokenRequestPayload := messages.RefreshAccessTokenRequestPayload{
		Refresh: messages.RefreshAccessTokenRequestRefresh{
			SessionId: sessionId,
			Nonces: messages.Nonces{
				Current:    &currentRefreshNonce,
				NextDigest: nextRefreshNonceDigest,
			},
		},
		Access: messages.RefreshAccessTokenRequestAccess{
			PublicKey: accessPublicKey,
		},
	}

	payloadJson, err = json.Marshal(refreshAccessTokenRequestPayload)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	signature, err = refreshKey.Sign(payloadJson)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	refreshAccessTokenRequest := &messages.RefreshAccessTokenRequest{
		Payload:   refreshAccessTokenRequestPayload,
		Signature: signature,
	}

	response, err = ba.RefreshAccessToken(refreshAccessTokenRequest, nil)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	refreshAccessTokenResponse := &messages.RefreshAccessTokenResponse{}
	if err := json.Unmarshal([]byte(response), refreshAccessTokenResponse); err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	accessTime := time.Now()
	nonce, err := salter.Generate128()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	testAccessPayload := FakeAccessRequestPayload{
		Access: messages.Access{
			Timestamp: accessTime.Format(time.RFC3339Nano),
			Nonce:     nonce,
		},
		Request: FakeAccessRequestRequest{
			Label: "value",
		},
	}

	payloadJson, err = json.Marshal(testAccessPayload)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	signature, err = accessKey.Sign(payloadJson)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	accessToken := refreshAccessTokenResponse.Payload.Access.Token
	accessVerifier := api.NewAccessVerifier(serverAccessKey, accessNonceStore, verifier)

	accessRequest := FakeAccessRequest{
		Token:     accessToken,
		Payload:   testAccessPayload,
		Signature: signature,
	}

	requestJson, err := json.Marshal(accessRequest)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	attributes, err := accessVerifier.Verify(requestJson)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	if attributes != nil {
		fmt.Printf("non-nil attributes")
		t.Fail()
	}
}

func TestPassphraseAccess(t *testing.T) {
	digester := cesrgolite.NewBlake3()
	salter := cesrgolite.NewSalter()
	passphraseVerifier := cesrgolite.NewEd25519Verifier()
	verifier := cesrgolite.NewSecp256r1Verifier()

	accessNonceStore := storage.NewInMemoryAccessNonceStore()
	authenticationNonceStore := storage.NewInMemoryAuthenticationNonceStore()
	refreshKeyStore := storage.NewInMemoryRefreshKeyStore(digester)
	refreshNonceStore := storage.NewInMemoryRefreshNonceStore(digester)
	passphraseAuthenticationKeyStore := storage.NewInMemoryPassphraseAuthenticationKeyStore(digester)
	passphraseRegistrationTokenStore := storage.NewInMemoryPassphraseRegistrationTokenStore()

	serverResponseKey, err := cesrgolite.NewSecp256r1()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	serverAccessKey, err := cesrgolite.NewSecp256r1()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	ba := api.NewBetterAuth(
		authenticationNonceStore,
		nil,
		passphraseAuthenticationKeyStore,
		passphraseRegistrationTokenStore,
		refreshNonceStore,
		refreshKeyStore,
		nil,
		digester,
		salter,
		passphraseVerifier,
		verifier,
		serverAccessKey,
		serverResponseKey,
	)

	response, err := ba.GeneratePassphraseRegistrationMaterials()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	generateResponse := &messages.PassphraseRegistrationMaterials{}
	if err := json.Unmarshal([]byte(response), generateResponse); err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	registrationToken := generateResponse.Payload.Registration.Token
	passphraseAuthenticationKey, err := cesrgolite.NewEd25519()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	passphraseAuthenticationPublicKey, err := passphraseAuthenticationKey.Public()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	registerPayload := messages.RegisterPassphraseAuthenticationKeyRequestPayload{
		Registration: messages.RegisterPassphraseAuthenticationKeyRequestRegistration{
			Token: registrationToken,
		},
		PassphraseAuthentication: messages.RegisterPassphraseAuthenticationKeyRequestPassphraseAuthentication{
			PublicKey: passphraseAuthenticationPublicKey,
		},
	}

	payloadJson, err := json.Marshal(registerPayload)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	signature, err := passphraseAuthenticationKey.Sign(payloadJson)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	registerRequest := &messages.RegisterPassphraseAuthenticationKeyRequest{
		Payload:   registerPayload,
		Signature: signature,
	}

	response, err = ba.RegisterPassphraseAuthenticationKey(registerRequest)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	registerResponse := &messages.RegisterPassphraseAuthenticationKeyResponse{}
	if err := json.Unmarshal([]byte(response), registerResponse); err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	accountId := registerResponse.Payload.Identification.AccountId

	beginRequest := &messages.BeginPassphraseAuthenticationRequest{
		Payload: messages.BeginPassphraseAuthenticationRequestPayload{
			Identification: messages.BeginPassphraseAuthenticationRequestIdentification{
				AccountId: accountId,
			},
		},
	}

	response, err = ba.BeginPassphraseAuthentication(beginRequest)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	beginResponse := &messages.BeginPassphraseAuthenticationResponse{}
	if err := json.Unmarshal([]byte(response), beginResponse); err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	refreshKey, err := cesrgolite.NewSecp256r1()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	refreshPublicKey, err := refreshKey.Public()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	nextRefreshNonce, err := salter.Generate128()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	nextRefreshNonceDigest := digester.Sum([]byte(nextRefreshNonce))

	completePayload := messages.CompletePassphraseAuthenticationRequestPayload{
		PassphraseAuthentication: messages.CompletePassphraseAuthenticationRequestPassphraseAuthentication{
			Nonce:     beginResponse.Payload.PassphraseAuthentication.Nonce,
			PublicKey: passphraseAuthenticationPublicKey,
		},
		Refresh: messages.CompletePassphraseAuthenticationRequestRefresh{
			PublicKey: refreshPublicKey,
			Nonces: messages.Nonces{
				NextDigest: nextRefreshNonceDigest,
			},
		},
	}

	payloadJson, err = json.Marshal(completePayload)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	signature, err = passphraseAuthenticationKey.Sign(payloadJson)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	completeRequest := &messages.CompletePassphraseAuthenticationRequest{
		Payload:   completePayload,
		Signature: signature,
	}

	response, err = ba.CompletePassphraseAuthentication(completeRequest)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	completeResponse := &messages.CompletePassphraseAuthenticationResponse{}
	if err := json.Unmarshal([]byte(response), completeResponse); err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	sessionId := completeResponse.Payload.Refresh.SessionId
	currentRefreshNonce := nextRefreshNonce
	nextRefreshNonce, err = salter.Generate128()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}
	nextRefreshNonceDigest = digester.Sum([]byte(nextRefreshNonce))

	accessKey, err := cesrgolite.NewSecp256r1()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	accessPublicKey, err := accessKey.Public()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	refreshAccessTokenRequestPayload := messages.RefreshAccessTokenRequestPayload{
		Refresh: messages.RefreshAccessTokenRequestRefresh{
			SessionId: sessionId,
			Nonces: messages.Nonces{
				Current:    &currentRefreshNonce,
				NextDigest: nextRefreshNonceDigest,
			},
		},
		Access: messages.RefreshAccessTokenRequestAccess{
			PublicKey: accessPublicKey,
		},
	}

	payloadJson, err = json.Marshal(refreshAccessTokenRequestPayload)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	signature, err = refreshKey.Sign(payloadJson)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	refreshAccessTokenRequest := &messages.RefreshAccessTokenRequest{
		Payload:   refreshAccessTokenRequestPayload,
		Signature: signature,
	}

	response, err = ba.RefreshAccessToken(refreshAccessTokenRequest, nil)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	refreshAccessTokenResponse := &messages.RefreshAccessTokenResponse{}
	if err := json.Unmarshal([]byte(response), refreshAccessTokenResponse); err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	accessTime := time.Now()
	nonce, err := salter.Generate128()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	testAccessPayload := FakeAccessRequestPayload{
		Access: messages.Access{
			Timestamp: accessTime.Format(time.RFC3339Nano),
			Nonce:     nonce,
		},
		Request: FakeAccessRequestRequest{
			Label: "value",
		},
	}

	payloadJson, err = json.Marshal(testAccessPayload)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	signature, err = accessKey.Sign(payloadJson)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	accessToken := refreshAccessTokenResponse.Payload.Access.Token
	accessVerifier := api.NewAccessVerifier(serverAccessKey, accessNonceStore, verifier)

	accessRequest := FakeAccessRequest{
		Token:     accessToken,
		Payload:   testAccessPayload,
		Signature: signature,
	}

	requestJson, err := json.Marshal(accessRequest)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	attributes, err := accessVerifier.Verify(requestJson)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		t.Fail()
	}

	if attributes != nil {
		fmt.Printf("non-nil attributes")
		t.Fail()
	}
}
