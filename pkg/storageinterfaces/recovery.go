package storageinterfaces

type RecoveryHashStore interface {
	Register(identity string, keyHash string) error
	Rotate(identity string, oldHash string, newHash string) error
	// Change forcefully changes the hash if the user loses access to the original
	Change(identity string, keyHash string) error
}
