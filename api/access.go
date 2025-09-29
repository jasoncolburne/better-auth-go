package api

import (
	"encoding/json"

	"github.com/jasoncolburne/better-auth-go/pkg/cryptointerfaces"
	"github.com/jasoncolburne/better-auth-go/pkg/encodinginterfaces"
	"github.com/jasoncolburne/better-auth-go/pkg/messages"
	"github.com/jasoncolburne/better-auth-go/pkg/storageinterfaces"
)

type AccessVerifier[T any] struct {
	crypto   *VerifierCryptoContainer
	encoding *VerifierEncodingContainer
	store    *VerifierStoreContainer
}

type VerifierCryptoContainer struct {
	PublicKey cryptointerfaces.VerificationKey
	Verifier  cryptointerfaces.Verifier
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
}

func NewAccessVerifier[T any](
	crypto *VerifierCryptoContainer,
	encoding *VerifierEncodingContainer,
	store *VerifierStoreContainer,
) *AccessVerifier[T] {
	return &AccessVerifier[T]{
		crypto:   crypto,
		encoding: encoding,
		store:    store,
	}
}

type AccessScanner[T any] = messages.AccessRequest[json.RawMessage, T]

func ParseAccessScanner[T any](message string) (*AccessScanner[T], error) {
	return messages.ParseAccessRequest(message, &AccessScanner[T]{})
}

func (av *AccessVerifier[T]) Verify(message string, attributes *T) (string, *T, error) {
	request, err := ParseAccessScanner[T](message)
	if err != nil {
		return "", attributes, nil
	}

	accessPublicKey, err := av.crypto.PublicKey.Public()
	if err != nil {
		return "", attributes, err
	}

	var identity string
	identity, attributes, err = request.VerifyAccess(
		av.store.AccessNonce,
		av.crypto.Verifier,
		av.crypto.PublicKey.Verifier(),
		accessPublicKey,
		av.encoding.TokenEncoder,
		av.encoding.Timestamper,
		attributes,
	)
	if err != nil {
		return "", attributes, err
	}

	return identity, attributes, nil
}
