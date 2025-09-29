package cryptointerfaces

type Hasher interface {
	Sum(message []byte) string
}
