package storage

import (
	"fmt"
	"time"
)

type InMemoryTimeLockStore struct {
	lifetime time.Duration
	values   map[string]time.Time
}

func NewInMemoryTimeLockStore(lifetime time.Duration) *InMemoryTimeLockStore {
	return &InMemoryTimeLockStore{
		lifetime: lifetime,
		values:   map[string]time.Time{},
	}
}

func (store *InMemoryTimeLockStore) Lifetime() time.Duration {
	return store.lifetime
}

func (store *InMemoryTimeLockStore) Reserve(value string) error {
	validAt, ok := store.values[value]

	if ok {
		now := time.Now()

		if now.Before(validAt) {
			return fmt.Errorf("value reserved too recently")
		}
	}

	newValidAt := time.Now().Add(store.lifetime)
	store.values[value] = newValidAt

	return nil
}
