package api

import (
	"time"

	"github.com/jasoncolburne/better-auth-go/pkg/cryptointerfaces"
	"github.com/jasoncolburne/better-auth-go/pkg/encodinginterfaces"
	"github.com/jasoncolburne/better-auth-go/pkg/storageinterfaces"
)

type BetterAuthServer[AttributesType any] struct {
	crypto   *CryptoContainer
	encoding *EncodingContainer
	expiry   *ExpiryContainer
	store    *StoresContainer
}

type CryptoContainer struct {
	Hasher   cryptointerfaces.Hasher
	KeyPair  *KeyPairContainer
	Noncer   cryptointerfaces.Noncer
	Verifier cryptointerfaces.Verifier
}

type ExpiryContainer struct {
	Access  time.Duration
	Refresh time.Duration
}

type KeyPairContainer struct {
	Access   cryptointerfaces.SigningKey
	Response cryptointerfaces.SigningKey
}

type EncodingContainer struct {
	IdentityVerifier encodinginterfaces.IdentityVerifier
	Timestamper      encodinginterfaces.Timestamper
	TokenEncoder     encodinginterfaces.TokenEncoder
}

type StoresContainer struct {
	Access         *AccessStoreContainer
	Authentication *AuthenticationStoreContainer
	Recovery       *RecoveryStoreContainer
}

type AccessStoreContainer struct {
	KeyHash storageinterfaces.TimeLockStore
}

type AuthenticationStoreContainer struct {
	Key   storageinterfaces.AuthenticationKeyStore
	Nonce storageinterfaces.AuthenticationNonceStore
}

type RecoveryStoreContainer struct {
	Hash storageinterfaces.RecoveryHashStore
}

func NewBetterAuthServer[AttributesType any](
	crypto *CryptoContainer,
	encoding *EncodingContainer,
	expiry *ExpiryContainer,
	store *StoresContainer,
) *BetterAuthServer[AttributesType] {
	return &BetterAuthServer[AttributesType]{
		crypto:   crypto,
		encoding: encoding,
		expiry:   expiry,
		store:    store,
	}
}

func (ba *BetterAuthServer[AttributesType]) responseKeyHash() (string, error) {
	responseKey, err := ba.crypto.KeyPair.Response.Public()
	if err != nil {
		return "", err
	}

	return ba.crypto.Hasher.Sum([]byte(responseKey)), nil
}
