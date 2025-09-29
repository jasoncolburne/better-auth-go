package storageinterfaces

type RecoveryHashStore interface {
	Register(identity string, keyHash string) error
	Validate(identity string, keyHash string) error
}
