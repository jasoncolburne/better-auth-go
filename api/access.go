package api

import (
	"encoding/json"

	"github.com/jasoncolburne/better-auth-go/pkg/cryptointerfaces"
	"github.com/jasoncolburne/better-auth-go/pkg/encodinginterfaces"
	"github.com/jasoncolburne/better-auth-go/pkg/messages"
	"github.com/jasoncolburne/better-auth-go/pkg/storageinterfaces"
)

type AccessVerifier[AttributesType any] struct {
	crypto   *VerifierCryptoContainer
	encoding *VerifierEncodingContainer
	store    *VerifierStoreContainer
}

type VerifierCryptoContainer struct {
	Verifier cryptointerfaces.Verifier
}

type VerifierCryptoPublicKey struct {
	Access cryptointerfaces.VerificationKey
}

type VerifierEncodingContainer struct {
	TokenEncoder encodinginterfaces.TokenEncoder
	Timestamper  encodinginterfaces.Timestamper
}

type VerifierStoreContainer struct {
	AccessNonce storageinterfaces.TimeLockStore
	AccessKey   storageinterfaces.VerificationKeyStore
}

func NewAccessVerifier[AttributesType any](
	crypto *VerifierCryptoContainer,
	encoding *VerifierEncodingContainer,
	store *VerifierStoreContainer,
) *AccessVerifier[AttributesType] {
	return &AccessVerifier[AttributesType]{
		crypto:   crypto,
		encoding: encoding,
		store:    store,
	}
}

type AccessScanner[AttributesType any] = messages.AccessRequest[json.RawMessage, AttributesType]

func ParseAccessScanner[AttributesType any](message string) (*AccessScanner[AttributesType], error) {
	return messages.ParseAccessRequest(message, &AccessScanner[AttributesType]{})
}

func (av *AccessVerifier[AttributesType]) Verify(message string, attributes *AttributesType) (json.RawMessage, *messages.AccessToken[AttributesType], string, error) {
	request, err := ParseAccessScanner[AttributesType](message)
	if err != nil {
		return nil, nil, "", err
	}

	token, err := request.VerifyAccess(
		av.store.AccessNonce,
		av.crypto.Verifier,
		av.store.AccessKey,
		av.encoding.TokenEncoder,
		av.encoding.Timestamper,
		attributes,
	)
	if err != nil {
		return nil, nil, "", err
	}

	return request.Payload.Request, token, request.Payload.Access.Nonce, nil
}
