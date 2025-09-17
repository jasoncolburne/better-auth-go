package storage

import "fmt"

type InMemoryAccessNonceStore struct {
	noncesByAccount map[string]map[string]bool
}

func NewInMemoryAccessNonceStore() *InMemoryAccessNonceStore {
	return &InMemoryAccessNonceStore{
		noncesByAccount: map[string]map[string]bool{},
	}
}

func (s *InMemoryAccessNonceStore) Reserve(accountId, nonce string) error {
	nonces, ok := s.noncesByAccount[accountId]
	if !ok {
		nonces = map[string]bool{}
	}

	present := nonces[nonce]
	if present {
		return fmt.Errorf("nonce already used")
	}

	nonces[nonce] = true
	s.noncesByAccount[accountId] = nonces

	return nil
}
