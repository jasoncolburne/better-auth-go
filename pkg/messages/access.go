package messages

import (
	"encoding/json"
	"fmt"

	"github.com/jasoncolburne/better-auth-go/pkg/cryptointerfaces"
	"github.com/jasoncolburne/better-auth-go/pkg/encodinginterfaces"
	"github.com/jasoncolburne/better-auth-go/pkg/storageinterfaces"
)

type AccessToken[AttributesType any] struct {
	ServerIdentity string         `json:"serverIdentity"`
	Device         string         `json:"device"`
	Identity       string         `json:"identity"`
	PublicKey      string         `json:"publicKey"`
	RotationHash   string         `json:"rotationHash"`
	IssuedAt       string         `json:"issuedAt"`
	Expiry         string         `json:"expiry"`
	RefreshExpiry  string         `json:"refreshExpiry"`
	Attributes     AttributesType `json:"attributes"`

	signature *string `json:"-"`
}

func NewAccessToken[AttributesType any](
	serverIdentity string,
	device string,
	identity string,
	publicKey string,
	rotationHash string,
	issuedAt string,
	expiry string,
	refreshExpiry string,
	attributes AttributesType,
) *AccessToken[AttributesType] {
	return &AccessToken[AttributesType]{
		ServerIdentity: serverIdentity,
		Device:         device,
		Identity:       identity,
		PublicKey:      publicKey,
		RotationHash:   rotationHash,
		IssuedAt:       issuedAt,
		Expiry:         expiry,
		RefreshExpiry:  refreshExpiry,
		Attributes:     attributes,
	}
}

func ParseAccessToken[AttributesType any](
	message string,
	tokenEncoder encodinginterfaces.TokenEncoder,
) (*AccessToken[AttributesType], error) {
	publicKeyLength, err := tokenEncoder.SignatureLength(message)
	if err != nil {
		return nil, err
	}

	signature := message[:publicKeyLength]
	rest := message[publicKeyLength:]

	tokenString, err := tokenEncoder.Decode(rest)
	if err != nil {
		return nil, err
	}

	accessToken := &AccessToken[AttributesType]{}
	if err := json.Unmarshal([]byte(tokenString), accessToken); err != nil {
		return nil, err
	}

	accessToken.signature = &signature

	return accessToken, nil
}

func (at *AccessToken[AttributesType]) SerializeToken(tokenEncoder encodinginterfaces.TokenEncoder) (string, error) {
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

func (at *AccessToken[AttributesType]) ComposePayload() (string, error) {
	composedPayload, err := json.Marshal(at)
	if err != nil {
		return "", err
	}

	return string(composedPayload), nil
}

func (at *AccessToken[AttributesType]) VerifyToken(
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

func (at *AccessToken[AttributesType]) Sign(signingKey cryptointerfaces.SigningKey) error {
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

type AccessRequest[PayloadType any, AttributesType any] SignableMessage[AccessRequestPayload[PayloadType]]

type AccessRequestPayload[PayloadType any] struct {
	Access  AccessRequestAccess `json:"access"`
	Request PayloadType         `json:"request"`
}

type AccessRequestAccess struct {
	Nonce     string `json:"nonce"`
	Timestamp string `json:"timestamp"`
	Token     string `json:"token"`
}

func NewAccessRequest[PayloadType any, AttributesType any, RequestType AccessRequest[PayloadType, AttributesType]](
	payload PayloadType,
	timestamper encodinginterfaces.Timestamper,
	token string,
	nonce string,
) *RequestType {
	return &RequestType{
		Payload: AccessRequestPayload[PayloadType]{
			Access: AccessRequestAccess{
				Nonce:     nonce,
				Timestamp: timestamper.Format(timestamper.Now()),
				Token:     token,
			},
			Request: payload,
		},
	}
}

func ParseAccessRequest[PayloadType any, AttributesType any, RequestType AccessRequest[PayloadType, AttributesType]](message string, u *RequestType) (*RequestType, error) {
	if err := json.Unmarshal([]byte(message), u); err != nil {
		return nil, err
	}

	return u, nil
}

func (ar *AccessRequest[PayloadType, AttributesType]) ComposePayload() (string, error) {
	composedPayload, err := json.Marshal(ar.Payload)
	if err != nil {
		return "", err
	}

	return string(composedPayload), nil
}

func (ar *AccessRequest[PayloadType, AttributesType]) Serialize() (string, error) {
	composedPayload, err := ar.ComposePayload()
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("{\"payload\":%s,\"signature\":\"%s\"}", composedPayload, *ar.Signature), nil
}

func (ar *AccessRequest[PayloadType, AttributesType]) Sign(signer cryptointerfaces.SigningKey) error {
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

func (ar *AccessRequest[PayloadType, AttributesType]) VerifyAccess(
	nonceStore storageinterfaces.TimeLockStore,
	verifier cryptointerfaces.Verifier,
	accessKeyStore storageinterfaces.VerificationKeyStore,
	tokenEncoder encodinginterfaces.TokenEncoder,
	timestamper encodinginterfaces.Timestamper,
	attributes *AttributesType,
) (*AccessToken[AttributesType], error) {
	accessToken, err := ParseAccessToken[AttributesType](
		ar.Payload.Access.Token,
		tokenEncoder,
	)
	if err != nil {
		return nil, err
	}

	accessKey, err := accessKeyStore.Get(accessToken.ServerIdentity)
	if err != nil {
		return nil, err
	}

	serverAccessPublicKey, err := accessKey.Public()
	if err != nil {
		return nil, err
	}

	if err := accessToken.VerifyToken(
		accessKey.Verifier(),
		serverAccessPublicKey,
		timestamper,
	); err != nil {
		return nil, err
	}

	composedPayload, err := ar.ComposePayload()
	if err != nil {
		return nil, err
	}

	if err := verifier.Verify(*ar.Signature, accessToken.PublicKey, []byte(composedPayload)); err != nil {
		return nil, err
	}

	now := timestamper.Now()

	accessTime, err := timestamper.Parse(ar.Payload.Access.Timestamp)
	if err != nil {
		return nil, err
	}

	expiry := accessTime.Add(nonceStore.Lifetime())

	if now.After(expiry) {
		return nil, fmt.Errorf("stale request")
	}

	if now.Before(accessTime) {
		return nil, fmt.Errorf("request from future")
	}

	if err := nonceStore.Reserve(ar.Payload.Access.Nonce); err != nil {
		return nil, err
	}

	return accessToken, nil
}
