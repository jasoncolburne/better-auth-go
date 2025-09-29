package storageinterfaces

type AuthenticationNonceStore interface {
	Generate(identity string) (string, error)
	Verify(nonce string) (string, error)
}

type AuthenticationKeyStore interface {
	Register(identity, device, current, nextDigest string, existingIdentity bool) error
	Rotate(identity, device, current, nextDigest string) error
	Public(identity, device string) (string, error)
}
