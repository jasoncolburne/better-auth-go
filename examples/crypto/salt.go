package crypto

import (
	"crypto/rand"
	"encoding/base64"
)

type Salter struct{}

func NewNoncer() *Salter {
	return &Salter{}
}

func (*Salter) Generate128() (string, error) {
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
