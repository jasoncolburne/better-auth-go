package storageinterfaces

import "context"

type AuthenticationNonceStore interface {
	Generate(ctx context.Context, identity string) (string, error)
	Verify(ctx context.Context, nonce string) (string, error)
}

type AuthenticationKeyStore interface {
	Register(ctx context.Context, identity, device, publicKey, rotationHash string, existingIdentity bool) error
	Rotate(ctx context.Context, identity, device, publicKey, rotationHash string) error
	Public(ctx context.Context, identity, device string) (string, error)
	RevokeDevice(ctx context.Context, identity, device string) error
	RevokeDevices(ctx context.Context, identity string) error
	DeleteIdentity(ctx context.Context, identity string) error
}
