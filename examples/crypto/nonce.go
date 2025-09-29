package crypto

import (
	"crypto/rand"
	"encoding/base64"
)

type Noncer struct{}

func NewNoncer() *Noncer {
	return &Noncer{}
}

func (*Noncer) Generate128() (string, error) {
	entropy := [18]byte{}

	_, err := rand.Read(entropy[2:])
	if err != nil {
		return "", err
	}

	salt := base64.URLEncoding.EncodeToString(entropy[:])
	runes := []rune(salt)
	runes[0] = '0'
	runes[1] = 'A'

	return string(runes), nil
}
