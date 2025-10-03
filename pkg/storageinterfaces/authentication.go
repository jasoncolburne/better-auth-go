package storageinterfaces

type AuthenticationNonceStore interface {
	Generate(identity string) (string, error)
	Verify(nonce string) (string, error)
}

type AuthenticationKeyStore interface {
	Register(identity, device, publicKey, rotationHash string, existingIdentity bool) error
	Rotate(identity, device, publicKey, rotationHash string) error
	Public(identity, device string) (string, error)
	RevokeDevice(identity, device string) error
	RevokeDevices(identity string) error
}
