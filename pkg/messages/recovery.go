package messages

// request

type RecoverAccountRequest = ClientRequest[RecoverAccountRequestPayload]

type RecoverAccountRequestPayload struct {
	Authentication RecoverAccountRequestAuthentication `json:"authentication"`
}

type RecoverAccountRequestAuthentication struct {
	Device       string `json:"device"`
	Identity     string `json:"identity"`
	PublicKey    string `json:"publicKey"`
	RecoveryHash string `json:"recoveryHash"`
	RecoveryKey  string `json:"recoveryKey"`
	RotationHash string `json:"rotationHash"`
}

func NewRecoverAccountRequest(payload RecoverAccountRequestPayload, nonce string) *RecoverAccountRequest {
	return NewClientRequest(payload, nonce)
}

func ParseRecoverAccountRequest(message string) (*RecoverAccountRequest, error) {
	return ParseClientRequest(message, &RecoverAccountRequest{})
}

// response

type RecoverAccountResponse = ServerResponse[RecoverAccountResponsePayload]

type RecoverAccountResponsePayload struct{}

func NewRecoverAccountResponse(
	payload RecoverAccountResponsePayload,
	serverIdentity string,
	nonce string,
) *RecoverAccountResponse {
	return NewServerResponse(payload, serverIdentity, nonce)
}

func ParseRecoverAccountResponse(message string) (*RecoverAccountResponse, error) {
	return ParseServerResponse(message, &RecoverAccountResponse{})
}
