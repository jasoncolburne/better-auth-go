package cryptointerfaces

type Digest interface {
	Sum(message []byte) string
}
