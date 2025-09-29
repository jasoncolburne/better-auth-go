package crypto

import (
	"encoding/base64"

	"github.com/zeebo/blake3"
)

type Blake3 struct{}

func NewBlake3() *Blake3 {
	return &Blake3{}
}

func (*Blake3) Sum(message []byte) string {
	bytes := make([]byte, 33)
	sum := blake3.Sum256(message)
	copy(bytes[1:33], sum[0:32])
	runes := []rune(base64.URLEncoding.EncodeToString(bytes))
	runes[0] = 'E'

	return string(runes)
}
