package storage

import (
	"fmt"

	"github.com/jasoncolburne/better-auth-go/examples/cesrgolite"
)

type InMemoryAuthenticationNonceStore struct {
	accountIdsByNonce map[string]string
}

func NewInMemoryAuthenticationNonceStore() *InMemoryAuthenticationNonceStore {
	return &InMemoryAuthenticationNonceStore{
		accountIdsByNonce: map[string]string{},
	}
}

func (s *InMemoryAuthenticationNonceStore) Generate(accountId string) (string, error) {
	salter := cesrgolite.NewSalter()

	nonce, err := salter.Generate128()
	if err != nil {
		return "", err
	}

	s.accountIdsByNonce[nonce] = accountId

	return nonce, nil
}

func (s *InMemoryAuthenticationNonceStore) Verify(nonce string) (string, error) {
	accountId, ok := s.accountIdsByNonce[nonce]
	if !ok {
		return "", fmt.Errorf("nonce not found")
	}

	return accountId, nil
}

func (s *InMemoryAuthenticationNonceStore) Invalidate(nonce string) {
	delete(s.accountIdsByNonce, nonce)
}
