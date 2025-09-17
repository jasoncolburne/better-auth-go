package cryptointerfaces

type KeyPair interface {
	Public() (string, error)
	Sign(message []byte) (string, error)
}
