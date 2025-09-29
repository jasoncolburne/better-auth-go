package messages

import (
	"encoding/json"
	"fmt"

	"github.com/jasoncolburne/better-auth-go/pkg/cryptointerfaces"
)

type Signable interface {
	ComposePayload() (string, error)
}

type Serializable interface {
	Serialize() (string, error)
}

type SignableMessage[T any] struct {
	Payload   T       `json:"payload"`
	Signature *string `json:"signature,omitempty"`
}

func (sm *SignableMessage[T]) ComposePayload() (string, error) {
	bytes, err := json.Marshal(sm.Payload)
	if err != nil {
		return "", err
	}

	return string(bytes), nil
}

func (sm *SignableMessage[T]) Serialize() (string, error) {
	composedPayload, err := sm.ComposePayload()
	if err != nil {
		return "", err
	}

	if sm.Signature == nil {
		return fmt.Sprintf("{\"payload\":%s}", composedPayload), nil
	}

	return fmt.Sprintf("{\"payload\":%s,\"signature\":\"%s\"}", composedPayload, *sm.Signature), nil
}

func (sm *SignableMessage[T]) Sign(signer cryptointerfaces.SigningKey) error {
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

func (sm *SignableMessage[T]) Verify(verifier cryptointerfaces.Verifier, publicKey string) error {
	if sm.Signature == nil {
		return fmt.Errorf("nil signature")
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

type ClientPayload[T any] struct {
	Access  ClientAccess `json:"access"`
	Request T            `json:"request"`
}

type ClientRequest[T any] = SignableMessage[ClientPayload[T]]

func NewClientRequest[T any, U ClientRequest[T]](payload T, nonce string) *U {
	return &U{
		Payload: ClientPayload[T]{
			Access: ClientAccess{
				Nonce: nonce,
			},
			Request: payload,
		},
	}
}

func ParseClientRequest[T any, U ClientRequest[T]](message string, u *U) (*U, error) {
	err := json.Unmarshal([]byte(message), u)
	if err != nil {
		return nil, err
	}

	return u, nil
}

type ServerAccess struct {
	Nonce           string `json:"nonce"`
	ResponseKeyHash string `json:"responseKeyHash"`
}

type ServerPayload[T any] struct {
	Access   ServerAccess `json:"access"`
	Response T            `json:"response"`
}

type ServerResponse[T any] = SignableMessage[ServerPayload[T]]

func NewServerResponse[T any, U ServerResponse[T]](payload T, responseKeyHash, nonce string) *U {
	return &U{
		Payload: ServerPayload[T]{
			Access: ServerAccess{
				Nonce:           nonce,
				ResponseKeyHash: responseKeyHash,
			},
			Response: payload,
		},
	}
}

func ParseServerResponse[T any, U ServerResponse[T]](message string, u *U) (*U, error) {
	err := json.Unmarshal([]byte(message), u)
	if err != nil {
		return nil, err
	}

	return u, nil
}
