package encoding

import (
	"fmt"
	"strings"

	"github.com/jasoncolburne/better-auth-go/pkg/cryptointerfaces"
)

type MockIdentityVerifier struct {
	hasher cryptointerfaces.Hasher
}

func NewMockIdentityVerifier(hasher cryptointerfaces.Hasher) *MockIdentityVerifier {
	return &MockIdentityVerifier{
		hasher: hasher,
	}
}

func (verifier *MockIdentityVerifier) Verify(identity, publicKey, rotationHash string, extraData *string) error {
	var message string

	message = fmt.Sprintf("%s%s", publicKey, rotationHash)
	if extraData != nil {
		message = fmt.Sprintf("%s%s", message, *extraData)
	}

	hash := verifier.hasher.Sum([]byte(message))
	if !strings.EqualFold(hash, identity) {
		return fmt.Errorf("invalid identity")
	}

	return nil
}
