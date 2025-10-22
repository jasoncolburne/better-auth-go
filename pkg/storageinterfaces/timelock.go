package storageinterfaces

import (
	"context"
	"time"
)

type TimeLockStore interface {
	Lifetime() time.Duration
	Reserve(ctx context.Context, value string) error
}
