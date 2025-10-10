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

// request

type DeleteAccountRequest = ClientRequest[DeleteAccountRequestPayload]

type DeleteAccountRequestPayload struct {
	Authentication DeleteAccountRequestAuthentication `json:"authentication"`
}

type DeleteAccountRequestAuthentication struct {
	Device       string `json:"device"`
	Identity     string `json:"identity"`
	PublicKey    string `json:"publicKey"`
	RotationHash string `json:"rotationHash"`
}

func NewDeleteAccountRequest(payload DeleteAccountRequestPayload, nonce string) *DeleteAccountRequest {
	return NewClientRequest(payload, nonce)
}

func ParseDeleteAccountRequest(message string) (*DeleteAccountRequest, error) {
	return ParseClientRequest(message, &DeleteAccountRequest{})
}

// response

type DeleteAccountResponse = ServerResponse[DeleteAccountResponsePayload]

type DeleteAccountResponsePayload struct{}

func NewDeleteAccountResponse(
	payload DeleteAccountResponsePayload,
	serverIdentity string,
	nonce string,
) *DeleteAccountResponse {
	return NewServerResponse(payload, serverIdentity, nonce)
}

func ParseDeleteAccountResponse(message string) (*DeleteAccountResponse, error) {
	return ParseServerResponse(message, &DeleteAccountResponse{})
}
