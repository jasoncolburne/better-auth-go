package storage

import (
	"fmt"
	"sync"
	"time"
)

type InMemoryTimeLockStore struct {
	mu       sync.RWMutex
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
	store.mu.Lock()
	defer store.mu.Unlock()

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
