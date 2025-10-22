package storage

import (
	"context"
	"fmt"
	"strings"
	"sync"
)

type InMemoryRecoveryHashStore struct {
	mu             sync.RWMutex
	dataByIdentity map[string]string
}

func NewInMemoryRecoveryHashStore() *InMemoryRecoveryHashStore {
	return &InMemoryRecoveryHashStore{
		dataByIdentity: map[string]string{},
	}
}

func (store *InMemoryRecoveryHashStore) Register(ctx context.Context, identity, hash string) error {
	store.mu.Lock()
	defer store.mu.Unlock()

	_, ok := store.dataByIdentity[identity]

	if ok {
		return fmt.Errorf("already exists")
	}

	store.dataByIdentity[identity] = hash

	return nil
}

func (store *InMemoryRecoveryHashStore) Rotate(ctx context.Context, identity, oldHash, newHash string) error {
	store.mu.Lock()
	defer store.mu.Unlock()

	stored, ok := store.dataByIdentity[identity]

	if !ok {
		return fmt.Errorf("not found")
	}

	if !strings.EqualFold(stored, oldHash) {
		return fmt.Errorf("incorrect hash")
	}

	store.dataByIdentity[identity] = newHash

	return nil
}

func (store *InMemoryRecoveryHashStore) Change(ctx context.Context, identity, keyHash string) error {
	store.mu.Lock()
	defer store.mu.Unlock()

	_, ok := store.dataByIdentity[identity]

	if !ok {
		return fmt.Errorf("not found")
	}

	store.dataByIdentity[identity] = keyHash

	return nil
}
