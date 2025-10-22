package storageinterfaces

import "context"

type RecoveryHashStore interface {
	Register(ctx context.Context, identity string, keyHash string) error
	Rotate(ctx context.Context, identity string, oldHash string, newHash string) error
	// Change forcefully changes the hash if the user loses access to the original
	Change(ctx context.Context, identity string, keyHash string) error
}
