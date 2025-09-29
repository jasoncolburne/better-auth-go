package cryptointerfaces

type VerificationKey interface {
	Verifier() Verifier
	Public() (string, error)
}
