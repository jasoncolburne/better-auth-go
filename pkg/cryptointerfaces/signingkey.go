package cryptointerfaces

type SigningKey interface {
	VerificationKey
	Sign(message []byte) (string, error)
}
