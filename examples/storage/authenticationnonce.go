package storage

import (
	"fmt"
	"sync"
	"time"

	"github.com/jasoncolburne/better-auth-go/examples/crypto"
	"github.com/jasoncolburne/better-auth-go/pkg/cryptointerfaces"
)

type InMemoryAuthenticationNonceStore struct {
	mu               sync.RWMutex
	dataByNonce      map[string]string
	lifetime         time.Duration
	nonceExpirations map[string]time.Time
	noncer           cryptointerfaces.Noncer
}

func NewInMemoryAuthenticationNonceStore(nonceLifetime time.Duration) *InMemoryAuthenticationNonceStore {
	return &InMemoryAuthenticationNonceStore{
		dataByNonce:      map[string]string{},
		lifetime:         nonceLifetime,
		nonceExpirations: map[string]time.Time{},
		noncer:           crypto.NewNoncer(),
	}
}

func (s *InMemoryAuthenticationNonceStore) Generate(identity string) (string, error) {
	nonce, err := s.noncer.Generate128()
	if err != nil {
		return "", err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.dataByNonce[nonce] = identity
	s.nonceExpirations[nonce] = time.Now().Add(s.lifetime)

	return nonce, nil
}

func (s *InMemoryAuthenticationNonceStore) Verify(nonce string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	identity, ok := s.dataByNonce[nonce]
	if !ok {
		return "", fmt.Errorf("nonce not found")
	}

	expiration, ok := s.nonceExpirations[nonce]
	if !ok {
		return "", fmt.Errorf("expiration not found")
	}

	if time.Now().After(expiration) {
		return "", fmt.Errorf("expired nonce")
	}

	return identity, nil
}
