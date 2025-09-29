package messages

// request

type StartAuthenticationRequest = ClientRequest[StartAuthenticationRequestPayload]

type StartAuthenticationRequestPayload struct {
	Authentication StartAuthenticationRequestAuthentication `json:"authentication"`
}

type StartAuthenticationRequestAuthentication struct {
	Identity string `json:"identity"`
}

func NewStartAuthenticationRequest(payload StartAuthenticationRequestPayload, nonce string) *StartAuthenticationRequest {
	return NewClientRequest(payload, nonce)
}

func ParseStartAuthenticationRequest(message string) (*StartAuthenticationRequest, error) {
	return ParseClientRequest(message, &StartAuthenticationRequest{})
}

// response

type StartAuthenticationResponse = ServerResponse[StartAuthenticationResponsePayload]

type StartAuthenticationResponsePayload struct {
	Authentication StartAuthenticationResponseAuthentication `json:"authentication"`
}

type StartAuthenticationResponseAuthentication struct {
	Nonce string `json:"nonce"`
}

func NewStartAuthenticationResponse(
	payload StartAuthenticationResponsePayload,
	responseKeyHash string,
	nonce string,
) *StartAuthenticationResponse {
	return NewServerResponse(payload, responseKeyHash, nonce)
}

func ParseStartAuthenticationResponse(message string) (*StartAuthenticationResponse, error) {
	return ParseServerResponse(message, &StartAuthenticationResponse{})
}

// request

type FinishAuthenticationRequest = ClientRequest[FinishAuthenticationRequestPayload]

type FinishAuthenticationRequestPayload struct {
	Access         FinishAuthenticationRequestAccess         `json:"access"`
	Authentication FinishAuthenticationRequestAuthentication `json:"authentication"`
}

type FinishAuthenticationRequestAccess struct {
	PublicKey    string `json:"publicKey"`
	RotationHash string `json:"rotationHash"`
}

type FinishAuthenticationRequestAuthentication struct {
	Device string `json:"device"`
	Nonce  string `json:"nonce"`
}

func NewFinishAuthenticationRequest(payload FinishAuthenticationRequestPayload, nonce string) *FinishAuthenticationRequest {
	return NewClientRequest(payload, nonce)
}

func ParseFinishAuthenticationRequest(message string) (*FinishAuthenticationRequest, error) {
	return ParseClientRequest(message, &FinishAuthenticationRequest{})
}

// response

type FinishAuthenticationResponse = ServerResponse[FinishAuthenticationResponsePayload]

type FinishAuthenticationResponsePayload struct {
	Access FinishAuthenticationResponseAccess `json:"access"`
}

type FinishAuthenticationResponseAccess struct {
	Token string `json:"token"`
}

func NewFinishAuthenticationResponse(
	payload FinishAuthenticationResponsePayload,
	responseKeyHash string,
	nonce string,
) *FinishAuthenticationResponse {
	return NewServerResponse(payload, responseKeyHash, nonce)
}

func ParseFinishAuthenticationResponse(message string) (*FinishAuthenticationResponse, error) {
	return ParseServerResponse(message, &FinishAuthenticationResponse{})
}
