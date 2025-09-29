package storage

import (
	"fmt"
	"strings"
)

type InMemoryRecoveryHashStore struct {
	dataByIdentity map[string]string
}

func NewInMemoryRecoveryHashStore() *InMemoryRecoveryHashStore {
	return &InMemoryRecoveryHashStore{
		dataByIdentity: map[string]string{},
	}
}

func (store *InMemoryRecoveryHashStore) Register(identity, hash string) error {
	_, ok := store.dataByIdentity[identity]

	if ok {
		return fmt.Errorf("already exists")
	}

	store.dataByIdentity[identity] = hash

	return nil
}

func (store *InMemoryRecoveryHashStore) Validate(identity, hash string) error {
	stored, ok := store.dataByIdentity[identity]

	if !ok {
		return fmt.Errorf("not found")
	}

	if !strings.EqualFold(stored, hash) {
		return fmt.Errorf("incorrect hash")
	}

	return nil
}
