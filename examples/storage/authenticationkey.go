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
	digester     cryptointerfaces.Digest
	knownDevices map[string]map[string]KeyState
}

func NewInMemoryAuthenticationKeyStore(digester cryptointerfaces.Digest) *InMemoryAuthenticationKeyStore {
	return &InMemoryAuthenticationKeyStore{
		digester:     digester,
		knownDevices: map[string]map[string]KeyState{},
	}
}

func (s *InMemoryAuthenticationKeyStore) Register(accountId, deviceId, current, nextDigest string) error {
	devices, ok := s.knownDevices[accountId]
	if !ok {
		devices = map[string]KeyState{}
	}

	_, ok = devices[deviceId]
	if ok {
		return fmt.Errorf("already registered")
	}

	devices[deviceId] = KeyState{
		current:    current,
		nextDigest: nextDigest,
	}

	s.knownDevices[accountId] = devices

	return nil
}

func (s *InMemoryAuthenticationKeyStore) Public(accountId, deviceId string) (string, error) {
	devices, ok := s.knownDevices[accountId]
	if !ok {
		return "", fmt.Errorf("account not found")
	}

	device, ok := devices[deviceId]
	if !ok {
		return "", fmt.Errorf("device not found")
	}

	return device.current, nil
}

func (s *InMemoryAuthenticationKeyStore) Rotate(accountId, deviceId, current, nextDigest string) error {
	devices, ok := s.knownDevices[accountId]
	if !ok {
		return fmt.Errorf("account not found")
	}

	device, ok := devices[deviceId]
	if !ok {
		return fmt.Errorf("device not found")
	}

	currentDigest := s.digester.Sum([]byte(current))

	if !strings.EqualFold(currentDigest, device.nextDigest) {
		return fmt.Errorf("digest mismatch")
	}

	devices[deviceId] = KeyState{
		current:    current,
		nextDigest: nextDigest,
	}

	s.knownDevices[accountId] = devices

	return nil
}
