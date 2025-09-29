package storageinterfaces

type AccessNonceStore interface {
	Reserve(identity, nonce string) error
}
