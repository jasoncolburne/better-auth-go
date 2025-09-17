package cryptointerfaces

type PublicKey interface {
	Public() (string, error)
}
