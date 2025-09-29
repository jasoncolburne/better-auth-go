package encodinginterfaces

type IdentityVerifier interface {
	Verify(identity, publicKey, rotationHash string, extraData *string) error
}
