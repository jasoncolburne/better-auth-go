package api

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/jasoncolburne/better-auth-go/api/accesstoken"
	"github.com/jasoncolburne/better-auth-go/pkg/cryptointerfaces"
	"github.com/jasoncolburne/better-auth-go/pkg/storageinterfaces"
	orderedmap "github.com/wk8/go-ordered-map/v2"
)

type AccessVerifier struct {
	accessTokenKey   cryptointerfaces.PublicKey
	accessNonceStore storageinterfaces.AccessNonceStore
	verification     cryptointerfaces.Verification
}

func NewAccessVerifier(
	accessTokenKey cryptointerfaces.PublicKey,
	accessNonceStore storageinterfaces.AccessNonceStore,
	verification cryptointerfaces.Verification,
) *AccessVerifier {
	return &AccessVerifier{
		accessTokenKey:   accessTokenKey,
		accessNonceStore: accessNonceStore,
		verification:     verification,
	}
}

func (av *AccessVerifier) Verify(token string, payload []byte, payloadSignature string, nonce string, accessTime *time.Time) (*orderedmap.OrderedMap[string, any], error) {
	decodedToken, signature, err := accesstoken.Decode(token)
	if err != nil {
		return nil, err
	}

	jsonToken, err := json.Marshal(decodedToken)
	if err != nil {
		return nil, err
	}

	publicKey, err := av.accessTokenKey.Public()
	if err != nil {
		return nil, err
	}

	if err := av.verification.Verify(signature, publicKey, jsonToken); err != nil {
		return nil, err
	}

	if err := av.verification.Verify(payloadSignature, decodedToken.PublicKey, payload); err != nil {
		return nil, err
	}

	if err := av.accessNonceStore.Reserve(decodedToken.AccountId, nonce); err != nil {
		return nil, err
	}

	if time.Now().After(accessTime.Add(30 * time.Second)) {
		return nil, fmt.Errorf("timed out")
	}

	expiry, err := time.Parse(time.RFC3339Nano, decodedToken.Expiry)
	if time.Now().After(expiry) {
		return nil, fmt.Errorf("token expired")
	}

	issuedAt, err := time.Parse(time.RFC3339Nano, decodedToken.IssuedAt)
	if time.Now().Before(issuedAt) {
		return nil, fmt.Errorf("token issued in the future")
	}

	return decodedToken.Attributes, nil
}
