package cryptointerfaces

type Verifier interface {
	Verify(signature, publicKey string, message []byte) error
}
