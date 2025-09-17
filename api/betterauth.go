package api

import (
	"github.com/jasoncolburne/better-auth-go/pkg/cryptointerfaces"
	"github.com/jasoncolburne/better-auth-go/pkg/storageinterfaces"
)

type BetterAuth struct {
	crypto *cryptoContainer
	stores *storesContainer
}

type cryptoContainer struct {
	keyPairs               *keyPairContainer
	digest                 cryptointerfaces.Digest
	salt                   cryptointerfaces.Salt
	passphraseVerification cryptointerfaces.Verification
	verification           cryptointerfaces.Verification
}

type keyPairContainer struct {
	response cryptointerfaces.KeyPair
	access   cryptointerfaces.KeyPair
}

type storesContainer struct {
	authenticationNonce         storageinterfaces.AuthenticationNonceStore
	authenticationKey           storageinterfaces.AuthenticationKeyStore
	passphraseAuthenticationKey storageinterfaces.PassphraseAuthenticationKeyStore
	passphraseRegistrationToken storageinterfaces.PassphraseRegistrationTokenStore
	refreshNonce                storageinterfaces.RefreshNonceStore
	refreshKey                  storageinterfaces.RefreshKeyStore
	registrationToken           storageinterfaces.RegistrationTokenStore
}

func NewBetterAuth(
	authenticationNonceStore storageinterfaces.AuthenticationNonceStore,
	authenticationKeyStore storageinterfaces.AuthenticationKeyStore,
	passphraseAuthenticationKeyStore storageinterfaces.PassphraseAuthenticationKeyStore,
	passphraseRegistrationTokenStore storageinterfaces.PassphraseRegistrationTokenStore,
	refreshNonceStore storageinterfaces.RefreshNonceStore,
	refreshKeyStore storageinterfaces.RefreshKeyStore,
	registrationTokenStore storageinterfaces.RegistrationTokenStore,
	digestInterface cryptointerfaces.Digest,
	saltInterface cryptointerfaces.Salt,
	passphraseVerificationInterface cryptointerfaces.Verification,
	verificationInterface cryptointerfaces.Verification,
	accessKey cryptointerfaces.KeyPair,
	responseKey cryptointerfaces.KeyPair,
) *BetterAuth {
	return &BetterAuth{
		crypto: &cryptoContainer{
			keyPairs: &keyPairContainer{
				access:   accessKey,
				response: responseKey,
			},
			digest:                 digestInterface,
			salt:                   saltInterface,
			passphraseVerification: passphraseVerificationInterface,
			verification:           verificationInterface,
		},
		stores: &storesContainer{
			authenticationNonce:         authenticationNonceStore,
			authenticationKey:           authenticationKeyStore,
			passphraseAuthenticationKey: passphraseAuthenticationKeyStore,
			passphraseRegistrationToken: passphraseRegistrationTokenStore,
			refreshNonce:                refreshNonceStore,
			refreshKey:                  refreshKeyStore,
			registrationToken:           registrationTokenStore,
		},
	}
}
