package storageinterfaces

type KeyPairStore interface {
	Generate(label string)
	Delete(label string)
	Public(label string) string
	Sign(label string, message []byte) string
}
