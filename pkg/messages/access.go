package messages

import (
	"encoding/json"
	"fmt"

	"github.com/jasoncolburne/better-auth-go/pkg/cryptointerfaces"
	"github.com/jasoncolburne/better-auth-go/pkg/encodinginterfaces"
	"github.com/jasoncolburne/better-auth-go/pkg/storageinterfaces"
)

type AccessToken[T any] struct {
	Identity      string `json:"identity"`
	PublicKey     string `json:"publicKey"`
	RotationHash  string `json:"rotationHash"`
	IssuedAt      string `json:"issuedAt"`
	Expiry        string `json:"expiry"`
	RefreshExpiry string `json:"refreshExpiry"`
	Attributes    T      `json:"attributes"`

	signature *string `json:"-"`
}

func NewAccessToken[T any](
	identity string,
	publicKey string,
	rotationHash string,
	issuedAt string,
	expiry string,
	refreshExpiry string,
	attributes T,
) *AccessToken[T] {
	return &AccessToken[T]{
		Identity:      identity,
		PublicKey:     publicKey,
		RotationHash:  rotationHash,
		IssuedAt:      issuedAt,
		Expiry:        expiry,
		RefreshExpiry: refreshExpiry,
		Attributes:    attributes,
	}
}

func ParseAccessToken[T any](
	message string,
	publicKeyLength int,
	tokenEncoder encodinginterfaces.TokenEncoder,
) (*AccessToken[T], error) {
	signature := message[:publicKeyLength]
	rest := message[publicKeyLength:]

	tokenString, err := tokenEncoder.Decode(rest)
	if err != nil {
		return nil, err
	}

	accessToken := &AccessToken[T]{}
	if err := json.Unmarshal([]byte(tokenString), accessToken); err != nil {
		return nil, err
	}

	accessToken.signature = &signature

	return accessToken, nil
}

func (at *AccessToken[T]) SerializeToken(tokenEncoder encodinginterfaces.TokenEncoder) (string, error) {
	if at.signature == nil {
		return "", fmt.Errorf("nil signature")
	}

	composedPayload, err := at.ComposePayload()
	if err != nil {
		return "", err
	}

	rawToken, err := tokenEncoder.Encode(string(composedPayload))
	if err != nil {
		return "", err
	}

	token := fmt.Sprintf("%s%s", *at.signature, rawToken)

	return token, nil
}

func (at *AccessToken[T]) ComposePayload() (string, error) {
	composedPayload, err := json.Marshal(at)
	if err != nil {
		return "", err
	}

	return string(composedPayload), nil
}

func (at *AccessToken[T]) VerifyToken(
	verifier cryptointerfaces.Verifier,
	publicKey string,
	timestamper encodinginterfaces.Timestamper,
) error {
	if at.signature == nil {
		return fmt.Errorf("nil signature")
	}

	composedPayload, err := at.ComposePayload()
	if err != nil {
		return err
	}

	if err := verifier.Verify(*at.signature, publicKey, []byte(composedPayload)); err != nil {
		return err
	}

	now := timestamper.Now()

	issuedAt, err := timestamper.Parse(at.IssuedAt)
	if err != nil {
		return err
	}

	expiry, err := timestamper.Parse(at.Expiry)
	if err != nil {
		return err
	}

	if now.Before(issuedAt) {
		return fmt.Errorf("token from future")
	}

	if now.After(expiry) {
		return fmt.Errorf("token expired")
	}

	return nil
}

func (at *AccessToken[T]) Sign(signingKey cryptointerfaces.SigningKey) error {
	composedPayload, err := at.ComposePayload()
	if err != nil {
		return err
	}

	signature, err := signingKey.Sign([]byte(composedPayload))
	if err != nil {
		return err
	}

	at.signature = &signature

	return nil
}

type AccessRequest[T any, U any] SignableMessage[AccessRequestPayload[T]]

type AccessRequestPayload[T any] struct {
	Access  AccessRequestAccess
	Request T
}

type AccessRequestAccess struct {
	Nonce     string
	Timestamp string
	Token     string
}

func NewAccessRequest[T any, U any, V AccessRequest[T, U]](
	payload T,
	timestamper encodinginterfaces.Timestamper,
	token string,
	nonce string,
) *V {
	return &V{
		Payload: AccessRequestPayload[T]{
			Access: AccessRequestAccess{
				Nonce:     nonce,
				Timestamp: timestamper.Format(timestamper.Now()),
				Token:     token,
			},
			Request: payload,
		},
	}
}

func ParseAccessRequest[T any, U AccessRequest[json.RawMessage, T]](message string, u *U) (*U, error) {
	if err := json.Unmarshal([]byte(message), u); err != nil {
		return nil, err
	}

	return u, nil
}

func (ar *AccessRequest[T, U]) ComposePayload() (string, error) {
	composedPayload, err := json.Marshal(ar.Payload)
	if err != nil {
		return "", err
	}

	return string(composedPayload), nil
}

func (ar *AccessRequest[T, U]) Serialize() (string, error) {
	composedPayload, err := ar.ComposePayload()
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("{\"payload\":%s,\"signature\":\"%s\"}", composedPayload, *ar.Signature), nil
}

func (ar *AccessRequest[T, U]) Sign(signer cryptointerfaces.SigningKey) error {
	composedPayload, err := ar.ComposePayload()
	if err != nil {
		return err
	}

	signature, err := signer.Sign([]byte(composedPayload))
	if err != nil {
		return err
	}

	ar.Signature = &signature

	return nil
}

func (ar *AccessRequest[T, U]) VerifyAccess(
	nonceStore storageinterfaces.TimeLockStore,
	verifier cryptointerfaces.Verifier,
	tokenVerifier cryptointerfaces.Verifier,
	serverAccessPublicKey string,
	tokenEncoder encodinginterfaces.TokenEncoder,
	timestamper encodinginterfaces.Timestamper,
	attributes *U,
) (string, *U, error) {
	accessToken, err := ParseAccessToken[U](
		ar.Payload.Access.Token,
		tokenVerifier.SignatureLength(),
		tokenEncoder,
	)
	if err != nil {
		return "", attributes, err
	}

	if err := accessToken.VerifyToken(
		tokenVerifier,
		serverAccessPublicKey,
		timestamper,
	); err != nil {
		return "", attributes, err
	}

	composedPayload, err := ar.ComposePayload()
	if err != nil {
		return "", attributes, err
	}

	if err := verifier.Verify(*ar.Signature, accessToken.PublicKey, []byte(composedPayload)); err != nil {
		return "", attributes, err
	}

	now := timestamper.Now()

	accessTime, err := timestamper.Parse(ar.Payload.Access.Timestamp)
	if err != nil {
		return "", attributes, err
	}

	expiry := accessTime.Add(nonceStore.Lifetime())

	if now.After(expiry) {
		return "", attributes, fmt.Errorf("stale request")
	}

	if now.Before(accessTime) {
		return "", attributes, fmt.Errorf("request from future")
	}

	if err := nonceStore.Reserve(ar.Payload.Access.Nonce); err != nil {
		return "", attributes, err
	}

	return accessToken.Identity, &accessToken.Attributes, nil
}
