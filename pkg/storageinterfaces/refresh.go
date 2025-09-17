package storageinterfaces

type RefreshNonceStore interface {
	Create(sessionId, nextDigest string) error
	Evolve(sessionId, current, nextDigest string) error
}

type RefreshKeyStore interface {
	Create(accountId, publicKey string) (sessionId string, err error)
	Get(sessionId string) (accountId, publicKey string, err error)
}
