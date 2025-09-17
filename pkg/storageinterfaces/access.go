package storageinterfaces

type AccessNonceStore interface {
	Reserve(accountId, nonce string) error
}
