package messages

// request

type RequestSessionRequest = ClientRequest[RequestSessionRequestPayload]

type RequestSessionRequestPayload struct {
	Authentication RequestSessionRequestAuthentication `json:"authentication"`
}

type RequestSessionRequestAuthentication struct {
	Identity string `json:"identity"`
}

func NewRequestSessionRequest(payload RequestSessionRequestPayload, nonce string) *RequestSessionRequest {
	return NewClientRequest(payload, nonce)
}

func ParseRequestSessionRequest(message string) (*RequestSessionRequest, error) {
	return ParseClientRequest(message, &RequestSessionRequest{})
}

// response

type RequestSessionResponse = ServerResponse[RequestSessionResponsePayload]

type RequestSessionResponsePayload struct {
	Authentication RequestSessionResponseAuthentication `json:"authentication"`
}

type RequestSessionResponseAuthentication struct {
	Nonce string `json:"nonce"`
}

func NewRequestSessionResponse(
	payload RequestSessionResponsePayload,
	serverIdentity string,
	nonce string,
) *RequestSessionResponse {
	return NewServerResponse(payload, serverIdentity, nonce)
}

func ParseRequestSessionResponse(message string) (*RequestSessionResponse, error) {
	return ParseServerResponse(message, &RequestSessionResponse{})
}

// request

type CreateSessionRequest = ClientRequest[CreateSessionRequestPayload]

type CreateSessionRequestPayload struct {
	Access         CreateSessionRequestAccess         `json:"access"`
	Authentication CreateSessionRequestAuthentication `json:"authentication"`
}

type CreateSessionRequestAccess struct {
	PublicKey    string `json:"publicKey"`
	RotationHash string `json:"rotationHash"`
}

type CreateSessionRequestAuthentication struct {
	Device string `json:"device"`
	Nonce  string `json:"nonce"`
}

func NewCreateSessionRequest(payload CreateSessionRequestPayload, nonce string) *CreateSessionRequest {
	return NewClientRequest(payload, nonce)
}

func ParseCreateSessionRequest(message string) (*CreateSessionRequest, error) {
	return ParseClientRequest(message, &CreateSessionRequest{})
}

// response

type CreateSessionResponse = ServerResponse[CreateSessionResponsePayload]

type CreateSessionResponsePayload struct {
	Access CreateSessionResponseAccess `json:"access"`
}

type CreateSessionResponseAccess struct {
	Token string `json:"token"`
}

func NewCreateSessionResponse(
	payload CreateSessionResponsePayload,
	serverIdentity string,
	nonce string,
) *CreateSessionResponse {
	return NewServerResponse(payload, serverIdentity, nonce)
}

func ParseCreateSessionResponse(message string) (*CreateSessionResponse, error) {
	return ParseServerResponse(message, &CreateSessionResponse{})
}

// request

type RefreshSessionRequest = ClientRequest[RefreshSessionRequestPayload]

type RefreshSessionRequestPayload struct {
	Access RefreshSessionRequestAccess `json:"access"`
}

type RefreshSessionRequestAccess struct {
	PublicKey    string `json:"publicKey"`
	RotationHash string `json:"rotationHash"`
	Token        string `json:"token"`
}

func NewRefreshSessionRequest(payload RefreshSessionRequestPayload, nonce string) *RefreshSessionRequest {
	return NewClientRequest(payload, nonce)
}

func ParseRefreshSessionRequest(message string) (*RefreshSessionRequest, error) {
	return ParseClientRequest(message, &RefreshSessionRequest{})
}

// response

type RefreshSessionResponse = ServerResponse[RefreshSessionResponsePayload]

type RefreshSessionResponsePayload struct {
	Access RefreshSessionResponseAccess `json:"access"`
}

type RefreshSessionResponseAccess struct {
	Token string `json:"token"`
}

func NewRefreshSessionResponse(
	payload RefreshSessionResponsePayload,
	serverIdentity string,
	nonce string,
) *RefreshSessionResponse {
	return NewServerResponse(payload, serverIdentity, nonce)
}

func ParseRefreshSessionResponse(message string) (*RefreshSessionResponse, error) {
	return ParseServerResponse(message, &RefreshSessionResponse{})
}
