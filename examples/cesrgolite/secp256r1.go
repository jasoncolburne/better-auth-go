package cesrgolite

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"math/big"
)

type Secp256r1 struct {
	private *ecdsa.PrivateKey
}

func NewSecp256r1() (*Secp256r1, error) {
	keyPair, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	return &Secp256r1{
		private: keyPair,
	}, nil
}

func (k *Secp256r1) Public() (string, error) {
	publicKey := k.private.PublicKey
	publicKeyBytes, err := publicKey.Bytes()
	if err != nil {
		return "", err
	}

	compressedKey, err := k.compressPublicKey(publicKeyBytes)
	if err != nil {
		return "", err
	}

	base64PublicKey := base64.URLEncoding.EncodeToString(compressedKey)
	cesrPublicKey := fmt.Sprintf("1AAI%s", base64PublicKey)

	return cesrPublicKey, nil
}

func (k *Secp256r1) compressPublicKey(pubKeyBytes []byte) ([]byte, error) {
	if len(pubKeyBytes) != 65 || pubKeyBytes[0] != 0x04 {
		return nil, fmt.Errorf("invalid uncompressed public key format")
	}

	x := new(big.Int).SetBytes(pubKeyBytes[1:33])
	y := new(big.Int).SetBytes(pubKeyBytes[33:65])

	curve := elliptic.P256()

	compressed := elliptic.MarshalCompressed(curve, x, y)

	return compressed, nil
}

type Secp256r1Signature struct {
	R, S *big.Int
}

func (k *Secp256r1) Sign(message []byte) (string, error) {
	digest := sha256.Sum256(message)

	asn1Signature, err := k.private.Sign(nil, digest[:], crypto.SHA256)
	if err != nil {
		return "", err
	}

	signature := Secp256r1Signature{}
	_, err = asn1.Unmarshal(asn1Signature, &signature)
	if err != nil {
		return "", err
	}

	signatureBytes := make([]byte, 66)
	copy(signatureBytes[2:34], signature.R.Bytes())
	copy(signatureBytes[34:66], signature.S.Bytes())

	base64Signature := base64.URLEncoding.EncodeToString(signatureBytes)
	runes := []rune(base64Signature)
	runes[0] = '0'
	runes[1] = 'I'

	return string(runes), nil
}

type Secp256r1Verifier struct {
}

func NewSecp256r1Verifier() *Secp256r1Verifier {
	return &Secp256r1Verifier{}
}

func (v *Secp256r1Verifier) Verify(signature, publicKey string, message []byte) error {
	publicKeyBytes, err := base64.URLEncoding.DecodeString(publicKey[4:])
	if err != nil {
		return err
	}

	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), publicKeyBytes)
	uncompressedKey := [65]byte{}
	uncompressedKey[0] = 4
	copy(uncompressedKey[1:33], x.Bytes())
	copy(uncompressedKey[33:65], y.Bytes())

	cryptoKey, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), uncompressedKey[:])
	if err != nil {
		return err
	}

	signatureBytes, err := base64.URLEncoding.DecodeString(signature)
	if err != nil {
		return err
	}

	r := big.Int{}
	s := big.Int{}

	r.SetBytes(signatureBytes[2:34])
	s.SetBytes(signatureBytes[34:66])

	digest := sha256.Sum256(message)
	if !ecdsa.Verify(cryptoKey, digest[:], &r, &s) {
		return fmt.Errorf("invalid signature")
	}

	return nil
}
