package storageinterfaces

type AuthenticationNonceStore interface {
	Generate(accountId string) (string, error)
	Verify(nonce string) (string, error)
	Invalidate(nonce string)
}

type AuthenticationKeyStore interface {
	Register(accountId, deviceId, current, nextDigest string) error
	Rotate(accountId, deviceId, current, nextDigest string) error
	Public(accountId, deviceId string) (string, error)
}

type PassphraseAuthenticationKeyStore interface {
	Commit(accountId, digest, salt, parameters string) error
	GetDerivationMaterial(accountId string) (string, string, error)
	VerifyPublicKey(accountId, publicKey string) error
}
