package storage

import (
	"crypto/rand"
	"fmt"

	"github.com/jasoncolburne/better-auth-go/pkg/cryptointerfaces"
)

type InMemoryRefreshKeyStore struct {
	digester        cryptointerfaces.Digest
	dataBySessionId map[string]RefreshKeyData
}

type RefreshKeyData struct {
	accountId string
	publicKey string
}

func NewInMemoryRefreshKeyStore(digester cryptointerfaces.Digest) *InMemoryRefreshKeyStore {
	return &InMemoryRefreshKeyStore{
		digester:        digester,
		dataBySessionId: map[string]RefreshKeyData{},
	}
}

func (s *InMemoryRefreshKeyStore) Create(accountId, publicKey string) (string, error) {
	entropy := [32]byte{}
	_, err := rand.Read(entropy[:])
	if err != nil {
		return "", err
	}

	sessionId := s.digester.Sum(entropy[:])

	s.dataBySessionId[sessionId] = RefreshKeyData{
		accountId: accountId,
		publicKey: publicKey,
	}

	return sessionId, nil
}

func (s *InMemoryRefreshKeyStore) Get(sessionId string) (string, string, error) {
	data, ok := s.dataBySessionId[sessionId]
	if !ok {
		return "", "", fmt.Errorf("session not found")
	}

	return data.accountId, data.publicKey, nil
}
