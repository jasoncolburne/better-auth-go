package cryptointerfaces

type Verification interface {
	Verify(signature, publicKey string, message []byte) error
}
