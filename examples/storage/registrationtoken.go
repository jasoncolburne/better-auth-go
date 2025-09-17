package storage

import (
	"crypto/rand"
	"fmt"

	"github.com/jasoncolburne/better-auth-go/examples/cesrgolite"
)

type InMemoryRegistrationTokenStore struct {
	accountIdsByToken map[string]string
}

func NewInMemoryRegistrationTokenStore() *InMemoryRegistrationTokenStore {
	return &InMemoryRegistrationTokenStore{
		accountIdsByToken: map[string]string{},
	}
}

func (s *InMemoryRegistrationTokenStore) Generate() (string, error) {
	entropy := [32]byte{}

	blake3 := cesrgolite.NewBlake3()

	_, err := rand.Read(entropy[:])
	if err != nil {
		return "", err
	}
	accountId := blake3.Sum(entropy[:])

	_, err = rand.Read(entropy[:])
	if err != nil {
		return "", err
	}
	token := blake3.Sum(entropy[:])

	s.accountIdsByToken[token] = accountId

	return token, nil
}

func (s *InMemoryRegistrationTokenStore) Validate(token string) (string, error) {
	accountId, ok := s.accountIdsByToken[token]
	if !ok {
		return "", fmt.Errorf("invalid token")
	}

	return accountId, nil
}

func (s *InMemoryRegistrationTokenStore) Invalidate(token string) {
	delete(s.accountIdsByToken, token)
}

type InMemoryPassphraseRegistrationTokenStore struct {
	dataByToken map[string]passphraseRegistrationData
}

type passphraseRegistrationData struct {
	accountId  string
	salt       string
	parameters string
}

func NewInMemoryPassphraseRegistrationTokenStore() *InMemoryPassphraseRegistrationTokenStore {
	return &InMemoryPassphraseRegistrationTokenStore{
		dataByToken: map[string]passphraseRegistrationData{},
	}
}

func (s *InMemoryPassphraseRegistrationTokenStore) Generate(salt, parameters string) (string, error) {
	entropy := [32]byte{}

	blake3 := cesrgolite.NewBlake3()

	_, err := rand.Read(entropy[:])
	if err != nil {
		return "", err
	}
	accountId := blake3.Sum(entropy[:])

	_, err = rand.Read(entropy[:])
	if err != nil {
		return "", err
	}
	token := blake3.Sum(entropy[:])

	s.dataByToken[token] = passphraseRegistrationData{
		accountId:  accountId,
		salt:       salt,
		parameters: parameters,
	}

	return token, nil
}

func (s *InMemoryPassphraseRegistrationTokenStore) Validate(token string) (string, string, string, error) {
	data, ok := s.dataByToken[token]
	if !ok {
		return "", "", "", fmt.Errorf("invalid token")
	}

	return data.accountId, data.salt, data.parameters, nil
}

func (s *InMemoryPassphraseRegistrationTokenStore) Invalidate(token string) {
	delete(s.dataByToken, token)
}
