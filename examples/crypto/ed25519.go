package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

type Ed25519 struct {
	public  ed25519.PublicKey
	private ed25519.PrivateKey
}

func NewEd25519() (*Ed25519, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	return &Ed25519{public: public, private: private}, nil
}

func (k *Ed25519) Public() (string, error) {
	bytes := [33]byte{}
	copy(bytes[1:], k.public)
	base64String := base64.URLEncoding.EncodeToString(bytes[:])
	runes := []rune(base64String)
	runes[0] = 'B'

	return string(runes), nil
}

func (k *Ed25519) Sign(message []byte) (string, error) {
	signature := [66]byte{}
	signatureBytes := ed25519.Sign(k.private, message)
	copy(signature[2:], signatureBytes)
	base64String := base64.URLEncoding.EncodeToString(signature[:])

	runes := []rune(base64String)
	runes[0] = '0'
	runes[1] = 'B'

	return string(runes), nil
}

type Ed25519Verifier struct{}

func NewEd25519Verifier() *Ed25519Verifier {
	return &Ed25519Verifier{}
}

func (*Ed25519Verifier) Verify(signature, publicKey string, message []byte) error {
	signatureBytes, err := base64.URLEncoding.DecodeString(signature)
	if err != nil {
		return err
	}

	publicKeyBytes, err := base64.URLEncoding.DecodeString(publicKey)
	if err != nil {
		return err
	}

	if !ed25519.Verify(ed25519.PublicKey(publicKeyBytes[1:]), message, signatureBytes[2:]) {
		return fmt.Errorf("invalid signature")
	}

	return nil
}
