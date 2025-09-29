package storage

import (
	"fmt"
	"strings"

	"github.com/jasoncolburne/better-auth-go/pkg/cryptointerfaces"
)

type KeyState struct {
	current    string
	nextDigest string
}

type InMemoryAuthenticationKeyStore struct {
	hasher       cryptointerfaces.Hasher
	knownDevices map[string]map[string]KeyState
}

func NewInMemoryAuthenticationKeyStore(hasher cryptointerfaces.Hasher) *InMemoryAuthenticationKeyStore {
	return &InMemoryAuthenticationKeyStore{
		hasher:       hasher,
		knownDevices: map[string]map[string]KeyState{},
	}
}

func (s *InMemoryAuthenticationKeyStore) Register(identity, device, current, nextDigest string, existingIdentity bool) error {
	devices, ok := s.knownDevices[identity]
	if !ok {
		devices = map[string]KeyState{}
	}

	_, ok = devices[device]
	if ok {
		return fmt.Errorf("already registered")
	}

	devices[device] = KeyState{
		current:    current,
		nextDigest: nextDigest,
	}

	s.knownDevices[identity] = devices

	return nil
}

func (s *InMemoryAuthenticationKeyStore) Public(identity, device string) (string, error) {
	devices, ok := s.knownDevices[identity]
	if !ok {
		return "", fmt.Errorf("account not found")
	}

	instance, ok := devices[device]
	if !ok {
		return "", fmt.Errorf("device not found")
	}

	return instance.current, nil
}

func (s *InMemoryAuthenticationKeyStore) Rotate(identity, device, current, nextDigest string) error {
	devices, ok := s.knownDevices[identity]
	if !ok {
		return fmt.Errorf("account not found")
	}

	instance, ok := devices[device]
	if !ok {
		return fmt.Errorf("device not found")
	}

	currentDigest := s.hasher.Sum([]byte(current))

	if !strings.EqualFold(currentDigest, instance.nextDigest) {
		return fmt.Errorf("hash mismatch")
	}

	devices[device] = KeyState{
		current:    current,
		nextDigest: nextDigest,
	}

	s.knownDevices[identity] = devices

	return nil
}
