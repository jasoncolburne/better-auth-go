package storage

import (
	"context"
	"fmt"
	"sync"

	"github.com/jasoncolburne/better-auth-go/pkg/cryptointerfaces"
)

type VerificationKeyStore struct {
	mu   sync.RWMutex
	keys map[string]cryptointerfaces.VerificationKey
}

func NewVerificationKeyStore() *VerificationKeyStore {
	return &VerificationKeyStore{
		keys: make(map[string]cryptointerfaces.VerificationKey),
	}
}

func (s *VerificationKeyStore) Add(identity string, key cryptointerfaces.VerificationKey) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.keys[identity] = key
}

func (s *VerificationKeyStore) Get(ctx context.Context, identity string) (cryptointerfaces.VerificationKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key, exists := s.keys[identity]
	if !exists {
		return nil, fmt.Errorf("key not found for identity: %s", identity)
	}
	return key, nil
}
