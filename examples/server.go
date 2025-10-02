package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/jasoncolburne/better-auth-go/api"
	"github.com/jasoncolburne/better-auth-go/examples/crypto"
	"github.com/jasoncolburne/better-auth-go/examples/encoding"
	"github.com/jasoncolburne/better-auth-go/examples/storage"
	"github.com/jasoncolburne/better-auth-go/pkg/cryptointerfaces"
	"github.com/jasoncolburne/better-auth-go/pkg/messages"
)

type MockTokenAttributes struct {
	PermissionsByRole map[string][]string `json:"permissionsByRole"`
}

type MockRequestPayload struct {
	Foo string `json:"foo"`
	Bar string `json:"bar"`
}

type MockResponsePayload struct {
	WasFoo string `json:"wasFoo"`
	WasBar string `json:"wasBar"`
}

type MockAccessRequest = messages.AccessRequest[MockRequestPayload, MockTokenAttributes]
type MockAccessResponse = messages.ServerResponse[MockResponsePayload]

type Server struct {
	ba                *api.BetterAuthServer[MockTokenAttributes]
	av                *api.AccessVerifier[MockTokenAttributes]
	serverResponseKey cryptointerfaces.SigningKey
}

func NewServer() (*Server, error) {
	accessLifetime := 15 * time.Minute
	accessWindow := 30 * time.Second
	refreshLifetime := 12 * time.Hour
	authenticationChallengeLifetime := 1 * time.Minute

	hasher := crypto.NewBlake3()
	verifier := crypto.NewSecp256r1Verifier()
	noncer := crypto.NewNoncer()

	accessKeyHashStore := storage.NewInMemoryTimeLockStore(refreshLifetime)
	accessNonceStore := storage.NewInMemoryTimeLockStore(accessWindow)
	authenticationKeyStore := storage.NewInMemoryAuthenticationKeyStore(hasher)
	authenticationNonceStore := storage.NewInMemoryAuthenticationNonceStore(authenticationChallengeLifetime)
	recoveryHashStore := storage.NewInMemoryRecoveryHashStore()

	identityVerifier := encoding.NewMockIdentityVerifier(hasher)
	timestamper := encoding.NewRfc3339Nano()
	tokenEncoder := encoding.NewTokenEncoder[MockTokenAttributes]()

	serverResponseKey, err := crypto.NewSecp256r1()
	if err != nil {
		return nil, err
	}

	serverAccessKey, err := crypto.NewSecp256r1()
	if err != nil {
		return nil, err
	}

	ba := api.NewBetterAuthServer[MockTokenAttributes](
		&api.CryptoContainer{
			Hasher: hasher,
			KeyPair: &api.KeyPairContainer{
				Access:   serverAccessKey,
				Response: serverResponseKey,
			},
			Noncer:   noncer,
			Verifier: verifier,
		},
		&api.EncodingContainer{
			IdentityVerifier: identityVerifier,
			Timestamper:      timestamper,
			TokenEncoder:     tokenEncoder,
		},
		&api.ExpiryContainer{
			Access:  accessLifetime,
			Refresh: refreshLifetime,
		},
		&api.StoresContainer{
			Access: &api.AccessStoreContainer{
				KeyHash: accessKeyHashStore,
			},
			Authentication: &api.AuthenticationStoreContainer{
				Key:   authenticationKeyStore,
				Nonce: authenticationNonceStore,
			},
			Recovery: &api.RecoveryStoreContainer{
				Hash: recoveryHashStore,
			},
		},
	)

	av := api.NewAccessVerifier[MockTokenAttributes](
		&api.VerifierCryptoContainer{
			PublicKey: serverAccessKey,
			Verifier:  verifier,
		},
		&api.VerifierEncodingContainer{
			TokenEncoder: tokenEncoder,
			Timestamper:  timestamper,
		},
		&api.VerifierStoreContainer{
			AccessNonce: accessNonceStore,
		},
	)

	return &Server{
		ba:                ba,
		av:                av,
		serverResponseKey: serverResponseKey,
	}, nil
}

func wrapResponse(w http.ResponseWriter, r *http.Request, logic func(message string) (string, error)) {
	var reply string

	message, err := io.ReadAll(r.Body)

	if err == nil {
		reply, err = logic(string(message))
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		reply = "{\"error\":\"an error occured\"}"
	}

	fmt.Fprintf(w, "%s", reply)
}

func (s *Server) create(w http.ResponseWriter, r *http.Request) {
	wrapResponse(w, r, s.ba.CreateAccount)
}

func (s *Server) recover(w http.ResponseWriter, r *http.Request) {
	wrapResponse(w, r, s.ba.RecoverAccount)
}

func (s *Server) link(w http.ResponseWriter, r *http.Request) {
	wrapResponse(w, r, s.ba.LinkDevice)
}

func (s *Server) unlink(w http.ResponseWriter, r *http.Request) {
	wrapResponse(w, r, s.ba.UnlinkDevice)
}

func (s *Server) startAuthentication(w http.ResponseWriter, r *http.Request) {
	wrapResponse(w, r, s.ba.StartAuthentication)
}

func (s *Server) finishAuthentication(w http.ResponseWriter, r *http.Request) {
	wrapResponse(w, r, func(message string) (string, error) {
		return s.ba.FinishAuthentication(message, MockTokenAttributes{
			PermissionsByRole: map[string][]string{
				"admin": {"read", "write"},
			},
		})
	})
}

func (s *Server) rotateAuthentication(w http.ResponseWriter, r *http.Request) {
	wrapResponse(w, r, s.ba.RotateAuthenticationKey)
}

func (s *Server) rotateAccess(w http.ResponseWriter, r *http.Request) {
	wrapResponse(w, r, s.ba.RefreshAccessToken)
}

func (s *Server) responseKey(w http.ResponseWriter, r *http.Request) {
	wrapResponse(w, r, func(message string) (string, error) {
		return s.serverResponseKey.Public()
	})
}

func (s *Server) respondToAccessRequest(message string, badNonce bool) (string, error) {
	_, _, err := s.av.Verify(message, &MockTokenAttributes{})
	if err != nil {
		return "", err
	}

	request, err := messages.ParseAccessRequest(message, &MockAccessRequest{})
	if err != nil {
		return "", err
	}

	responsePublicKey, err := s.serverResponseKey.Public()
	if err != nil {
		return "", err
	}

	hasher := crypto.NewBlake3()
	responseKeyHash := hasher.Sum([]byte(responsePublicKey))

	nonce := request.Payload.Access.Nonce
	if badNonce {
		nonce = "0A0123456789"
	}

	response := messages.NewServerResponse(
		MockResponsePayload{
			WasFoo: request.Payload.Request.Foo,
			WasBar: request.Payload.Request.Bar,
		},
		responseKeyHash,
		nonce,
	)

	if err := response.Sign(s.serverResponseKey); err != nil {
		return "", err
	}

	reply, err := response.Serialize()
	if err != nil {
		return "", err
	}

	return reply, nil
}

func (s *Server) fooBar(w http.ResponseWriter, r *http.Request) {
	wrapResponse(w, r, func(message string) (string, error) {
		return s.respondToAccessRequest(message, false)
	})
}

func (s *Server) badNonce(w http.ResponseWriter, r *http.Request) {
	wrapResponse(w, r, func(message string) (string, error) {
		return s.respondToAccessRequest(message, true)
	})
}

func (s *Server) StartServer() error {
	http.HandleFunc("/account/create", s.create)

	http.HandleFunc("/authenticate/start", s.startAuthentication)
	http.HandleFunc("/authenticate/finish", s.finishAuthentication)

	http.HandleFunc("/rotate/authentication", s.rotateAuthentication)
	http.HandleFunc("/rotate/access", s.rotateAccess)
	http.HandleFunc("/rotate/recover", s.recover)
	http.HandleFunc("/rotate/link", s.link)
	http.HandleFunc("/rotate/unlink", s.unlink)

	http.HandleFunc("/key/response", s.responseKey)

	http.HandleFunc("/foo/bar", s.fooBar)
	http.HandleFunc("/bad/nonce", s.badNonce)

	return http.ListenAndServe("localhost:8080", nil)
}

func main() {
	server, err := NewServer()
	if err != nil {
		panic(err)
	}

	if err := server.StartServer(); err != nil {
		panic(err)
	}
}
