package storageinterfaces

type RefreshNonceStore interface {
	Create(sessionId, nextDigest string) error
	Evolve(sessionId, current, nextDigest string) error
}
