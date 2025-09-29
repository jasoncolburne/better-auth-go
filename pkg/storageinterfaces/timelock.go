package storageinterfaces

import "time"

type TimeLockStore interface {
	Lifetime() time.Duration
	Reserve(value string) error
}
