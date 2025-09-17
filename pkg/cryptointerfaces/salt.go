package cryptointerfaces

type Salt interface {
	Generate128() (string, error)
}
