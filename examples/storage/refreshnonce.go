package storage

import (
	"fmt"
	"strings"

	"github.com/jasoncolburne/better-auth-go/pkg/cryptointerfaces"
)

type InMemoryRefreshNonceStore struct {
	digester              cryptointerfaces.Digest
	nextDigestBySessionId map[string]string
}

func NewInMemoryRefreshNonceStore(digester cryptointerfaces.Digest) *InMemoryRefreshNonceStore {
	return &InMemoryRefreshNonceStore{
		digester:              digester,
		nextDigestBySessionId: map[string]string{},
	}
}

func (s *InMemoryRefreshNonceStore) Create(sessionId, nextDigest string) error {
	s.nextDigestBySessionId[sessionId] = nextDigest

	return nil
}

func (s *InMemoryRefreshNonceStore) Evolve(sessionId, current, nextDigest string) error {
	existingDigest, ok := s.nextDigestBySessionId[sessionId]
	if !ok {
		return fmt.Errorf("session not found")
	}

	newDigest := s.digester.Sum([]byte(current))

	if !strings.EqualFold(existingDigest, newDigest) {
		return fmt.Errorf("digest mismatch")
	}

	s.nextDigestBySessionId[sessionId] = nextDigest

	return nil
}
