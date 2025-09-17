package storage

import (
	"fmt"
	"strings"

	"github.com/jasoncolburne/better-auth-go/pkg/cryptointerfaces"
)

type InMemoryPassphraseAuthenticationKeyStore struct {
	digester        cryptointerfaces.Digest
	dataByAccountId map[string]PassphraseKeyData
}

type PassphraseKeyData struct {
	publicKeyDigest string
	salt            string
	parameters      string
}

func NewInMemoryPassphraseAuthenticationKeyStore(digester cryptointerfaces.Digest) *InMemoryPassphraseAuthenticationKeyStore {
	return &InMemoryPassphraseAuthenticationKeyStore{
		digester:        digester,
		dataByAccountId: map[string]PassphraseKeyData{},
	}
}

func (s *InMemoryPassphraseAuthenticationKeyStore) Commit(accountId, digest, salt, parameters string) error {
	s.dataByAccountId[accountId] = PassphraseKeyData{
		publicKeyDigest: digest,
		salt:            salt,
		parameters:      parameters,
	}

	return nil
}

func (s *InMemoryPassphraseAuthenticationKeyStore) GetDerivationMaterial(accountId string) (string, string, error) {
	data, ok := s.dataByAccountId[accountId]
	if !ok {
		return "", "", fmt.Errorf("registration not found")
	}

	return data.salt, data.parameters, nil
}

func (s *InMemoryPassphraseAuthenticationKeyStore) VerifyPublicKey(accountId, publicKey string) error {
	data, ok := s.dataByAccountId[accountId]
	if !ok {
		return fmt.Errorf("registration not found")
	}

	digest := s.digester.Sum([]byte(publicKey))

	if !strings.EqualFold(digest, data.publicKeyDigest) {
		return fmt.Errorf("digest mismatch")
	}

	return nil
}
