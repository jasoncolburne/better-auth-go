package messages

// request

type RotateAuthenticationKeyRequest = ClientRequest[RotateAuthenticationKeyRequestPayload]

type RotateAuthenticationKeyRequestPayload struct {
	Authentication RotateAuthenticationKeyRequestAuthentication `json:"authentication"`
}

type RotateAuthenticationKeyRequestAuthentication struct {
	Device       string `json:"device"`
	Identity     string `json:"identity"`
	PublicKey    string `json:"publicKey"`
	RotationHash string `json:"rotationHash"`
}

func NewRotateAuthenticationKeyRequest(
	payload RotateAuthenticationKeyRequestPayload,
	nonce string,
) *RotateAuthenticationKeyRequest {
	return NewClientRequest(payload, nonce)
}

func ParseRotateAuthenticationKeyRequest(message string) (*RotateAuthenticationKeyRequest, error) {
	return ParseClientRequest(message, &RotateAuthenticationKeyRequest{})
}

// response

type RotateAuthenticationKeyResponse = ServerResponse[RotateAuthenticationKeyResponsePayload]

type RotateAuthenticationKeyResponsePayload struct{}

func NewRotateAuthenticationKeyResponse(
	payload RotateAuthenticationKeyResponsePayload,
	serverIdentity string,
	nonce string,
) *RotateAuthenticationKeyResponse {
	return NewServerResponse(payload, serverIdentity, nonce)
}

func ParseRotateAuthenticationKeyResponse(message string) (*RotateAuthenticationKeyResponse, error) {
	return ParseServerResponse(message, &RotateAuthenticationKeyResponse{})
}
