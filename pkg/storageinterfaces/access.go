package storageinterfaces

import "context"

type AccessNonceStore interface {
	Reserve(ctx context.Context, identity, nonce string) error
}
