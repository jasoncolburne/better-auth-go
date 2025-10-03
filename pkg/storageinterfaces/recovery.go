package storageinterfaces

type RecoveryHashStore interface {
	Register(identity string, keyHash string) error
	Rotate(identity string, oldHash string, newHash string) error
}
