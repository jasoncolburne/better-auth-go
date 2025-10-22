package storageinterfaces

import (
	"context"

	"github.com/jasoncolburne/better-auth-go/pkg/cryptointerfaces"
)

type VerificationKeyStore interface {
	Get(ctx context.Context, identity string) (cryptointerfaces.VerificationKey, error)
}
