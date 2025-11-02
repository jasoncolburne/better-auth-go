package messages

import (
	"encoding/json"
	"fmt"

	"github.com/jasoncolburne/better-auth-go/pkg/cryptointerfaces"
	"github.com/jasoncolburne/better-auth-go/pkg/errors"
)

type Signable interface {
	ComposePayload() (string, error)
}

type Serializable interface {
	Serialize() (string, error)
}

type SignableMessage[PayloadType any] struct {
	Payload   PayloadType `json:"payload"`
	Signature *string     `json:"signature,omitempty"`
}

func (sm *SignableMessage[PayloadType]) ComposePayload() (string, error) {
	bytes, err := json.Marshal(sm.Payload)
	if err != nil {
		return "", err
	}

	return string(bytes), nil
}

func (sm *SignableMessage[PayloadType]) Serialize() (string, error) {
	composedPayload, err := sm.ComposePayload()
	if err != nil {
		return "", err
	}

	if sm.Signature == nil {
		return fmt.Sprintf("{\"payload\":%s}", composedPayload), nil
	}

	return fmt.Sprintf("{\"payload\":%s,\"signature\":\"%s\"}", composedPayload, *sm.Signature), nil
}

func (sm *SignableMessage[PayloadType]) Sign(signer cryptointerfaces.SigningKey) error {
	composedPayload, err := sm.ComposePayload()
	if err != nil {
		return err
	}

	signature, err := signer.Sign([]byte(composedPayload))
	if err != nil {
		return err
	}

	sm.Signature = &signature

	return nil
}

func (sm *SignableMessage[PayloadType]) Verify(verifier cryptointerfaces.Verifier, publicKey string) error {
	if sm.Signature == nil {
		return errors.NewInvalidMessageError("signature", "signature is null")
	}

	composedPayload, err := sm.ComposePayload()
	if err != nil {
		return err
	}

	return verifier.Verify(*sm.Signature, publicKey, []byte(composedPayload))
}

type ClientAccess struct {
	Nonce string `json:"nonce"`
}

type ClientPayload[PayloadType any] struct {
	Access  ClientAccess `json:"access"`
	Request PayloadType  `json:"request"`
}

type ClientRequest[PayloadType any] = SignableMessage[ClientPayload[PayloadType]]

func NewClientRequest[PayloadType any, RequestType ClientRequest[PayloadType]](payload PayloadType, nonce string) *RequestType {
	return &RequestType{
		Payload: ClientPayload[PayloadType]{
			Access: ClientAccess{
				Nonce: nonce,
			},
			Request: payload,
		},
	}
}

func ParseClientRequest[PayloadType any, RequestType ClientRequest[PayloadType]](message string, u *RequestType) (*RequestType, error) {
	err := json.Unmarshal([]byte(message), u)
	if err != nil {
		return nil, err
	}

	return u, nil
}

type ServerAccess struct {
	Nonce          string `json:"nonce"`
	ServerIdentity string `json:"serverIdentity"`
}

type ServerPayload[PayloadType any] struct {
	Access   ServerAccess `json:"access"`
	Response PayloadType  `json:"response"`
}

type ServerResponse[PayloadType any] = SignableMessage[ServerPayload[PayloadType]]

func NewServerResponse[PayloadType any, ResponseType ServerResponse[PayloadType]](
	payload PayloadType,
	serverIdentity,
	nonce string,
) *ResponseType {
	return &ResponseType{
		Payload: ServerPayload[PayloadType]{
			Access: ServerAccess{
				Nonce:          nonce,
				ServerIdentity: serverIdentity,
			},
			Response: payload,
		},
	}
}

func ParseServerResponse[PayloadType any, ResponseType ServerResponse[PayloadType]](message string, u *ResponseType) (*ResponseType, error) {
	err := json.Unmarshal([]byte(message), u)
	if err != nil {
		return nil, err
	}

	return u, nil
}
