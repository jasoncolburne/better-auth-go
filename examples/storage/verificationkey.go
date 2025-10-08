package storage

import (
	"fmt"

	"github.com/jasoncolburne/better-auth-go/pkg/cryptointerfaces"
)

type VerificationKeyStore struct {
	keys map[string]cryptointerfaces.VerificationKey
}

func NewVerificationKeyStore() *VerificationKeyStore {
	return &VerificationKeyStore{
		keys: make(map[string]cryptointerfaces.VerificationKey),
	}
}

func (s *VerificationKeyStore) Add(identity string, key cryptointerfaces.VerificationKey) {
	s.keys[identity] = key
}

func (s *VerificationKeyStore) Get(identity string) (cryptointerfaces.VerificationKey, error) {
	key, exists := s.keys[identity]
	if !exists {
		return nil, fmt.Errorf("key not found for identity: %s", identity)
	}
	return key, nil
}
