package storageinterfaces

import "github.com/jasoncolburne/better-auth-go/pkg/cryptointerfaces"

type VerificationKeyStore interface {
	Get(identity string) (cryptointerfaces.VerificationKey, error)
}
