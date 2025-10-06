package messages

// request

type RefreshAccessTokenRequest = ClientRequest[RefreshAccessTokenRequestPayload]

type RefreshAccessTokenRequestPayload struct {
	Access RefreshAccessTokenRequestAccess `json:"access"`
}

type RefreshAccessTokenRequestAccess struct {
	PublicKey    string `json:"publicKey"`
	RotationHash string `json:"rotationHash"`
	Token        string `json:"token"`
}

func NewRefreshAccessTokenRequest(payload RefreshAccessTokenRequestPayload, nonce string) *RefreshAccessTokenRequest {
	return NewClientRequest(payload, nonce)
}

func ParseRefreshAccessTokenRequest(message string) (*RefreshAccessTokenRequest, error) {
	return ParseClientRequest(message, &RefreshAccessTokenRequest{})
}

// response

type RefreshAccessTokenResponse = ServerResponse[RefreshAccessTokenResponsePayload]

type RefreshAccessTokenResponsePayload struct {
	Access RefreshAccessTokenResponseAccess `json:"access"`
}

type RefreshAccessTokenResponseAccess struct {
	Token string `json:"token"`
}

func NewRefreshAccessTokenResponse(
	payload RefreshAccessTokenResponsePayload,
	serverIdentity string,
	nonce string,
) *RefreshAccessTokenResponse {
	return NewServerResponse(payload, serverIdentity, nonce)
}

func ParseRefreshAccessTokenResponse(message string) (*RefreshAccessTokenResponse, error) {
	return ParseServerResponse(message, &RefreshAccessTokenResponse{})
}
