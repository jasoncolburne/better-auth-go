package messages

// request

type CreateAccountRequest = ClientRequest[CreateAccountRequestPayload]

type CreateAccountRequestPayload struct {
	Authentication CreateAccountRequestAuthentication `json:"authentication"`
}

type CreateAccountRequestAuthentication struct {
	Device       string `json:"device"`
	Identity     string `json:"identity"`
	PublicKey    string `json:"publicKey"`
	RecoveryHash string `json:"recoveryHash"`
	RotationHash string `json:"rotationHash"`
}

func NewCreateAccountRequest(payload CreateAccountRequestPayload, nonce string) *CreateAccountRequest {
	return NewClientRequest(payload, nonce)
}

func ParseCreateAccountRequest(message string) (*CreateAccountRequest, error) {
	return ParseClientRequest(message, &CreateAccountRequest{})
}

// response

type CreateAccountResponse = ServerResponse[CreateAccountResponsePayload]

type CreateAccountResponsePayload struct{}

func NewCreateAccountResponse(
	payload CreateAccountResponsePayload,
	serverIdentity string,
	nonce string,
) *CreateAccountResponse {
	return NewServerResponse(payload, serverIdentity, nonce)
}

func ParseCreateAccountResponse(message string) (*CreateAccountResponse, error) {
	return ParseServerResponse(message, &CreateAccountResponse{})
}
