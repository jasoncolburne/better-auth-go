package storage

import (
	"fmt"
	"strings"

	"github.com/jasoncolburne/better-auth-go/pkg/cryptointerfaces"
)

type KeyState struct {
	current      string
	rotationHash string
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

func (s *InMemoryAuthenticationKeyStore) Register(identity, device, current, rotationHash string, existingIdentity bool) error {
	devices, ok := s.knownDevices[identity]
	if !ok {
		devices = map[string]KeyState{}
	}

	_, ok = devices[device]
	if ok {
		return fmt.Errorf("already registered")
	}

	devices[device] = KeyState{
		current:      current,
		rotationHash: rotationHash,
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

func (s *InMemoryAuthenticationKeyStore) Rotate(identity, device, publicKey, rotationHash string) error {
	devices, ok := s.knownDevices[identity]
	if !ok {
		return fmt.Errorf("account not found")
	}

	instance, ok := devices[device]
	if !ok {
		return fmt.Errorf("device not found")
	}

	hash := s.hasher.Sum([]byte(publicKey))

	if !strings.EqualFold(hash, instance.rotationHash) {
		return fmt.Errorf("hash mismatch")
	}

	devices[device] = KeyState{
		current:      publicKey,
		rotationHash: rotationHash,
	}

	s.knownDevices[identity] = devices

	return nil
}

func (s *InMemoryAuthenticationKeyStore) RevokeDevice(identity, device string) error {
	devices, ok := s.knownDevices[identity]
	if !ok {
		return fmt.Errorf("account not found")
	}

	delete(devices, device)

	s.knownDevices[identity] = devices

	return nil
}

func (s *InMemoryAuthenticationKeyStore) RevokeDevices(identity string) error {
	s.knownDevices[identity] = map[string]KeyState{}

	return nil
}
