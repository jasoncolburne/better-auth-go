package cryptointerfaces

type Noncer interface {
	Generate128() (string, error)
}
