package storageinterfaces

type AuthenticationNonceStore interface {
	Generate(accountId string) (string, error)
	Verify(nonce string) (string, error)
}

type AuthenticationKeyStore interface {
	Register(accountId, deviceId, current, nextDigest string, existingIdentity bool) error
	Rotate(accountId, deviceId, current, nextDigest string) error
	Public(accountId, deviceId string) (string, error)
}
