package cryptointerfaces

type SigningKey interface {
	VerificationKey
	Identity() (string, error)
	Sign(message []byte) (string, error)
}
