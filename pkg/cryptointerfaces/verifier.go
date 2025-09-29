package cryptointerfaces

type Verifier interface {
	SignatureLength() int
	Verify(signature, publicKey string, message []byte) error
}
