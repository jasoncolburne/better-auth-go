package messages

type LinkContainer = SignableMessage[LinkContainerPayload]

type LinkContainerPayload struct {
	Authentication LinkContainerAuthentication `json:"authentication"`
}

type LinkContainerAuthentication struct {
	Device       string `json:"device"`
	Identity     string `json:"identity"`
	PublicKey    string `json:"publicKey"`
	RotationHash string `json:"rotationHash"`
}

func NewLinkContainer(payload LinkContainerPayload, signature *string) *LinkContainer {
	return &LinkContainer{
		Payload:   payload,
		Signature: signature,
	}
}

// request

type LinkDeviceRequest = ClientRequest[LinkDeviceRequestPayload]

type LinkDeviceRequestPayload struct {
	Authentication LinkDeviceRequestAuthentication `json:"authentication"`
	Link           LinkContainer                   `json:"link"`
}

type LinkDeviceRequestAuthentication struct {
	Device       string `json:"device"`
	Identity     string `json:"identity"`
	PublicKey    string `json:"publicKey"`
	RotationHash string `json:"rotationHash"`
}

func NewLinkDeviceRequest(payload LinkDeviceRequestPayload, nonce string) *LinkDeviceRequest {
	return NewClientRequest(payload, nonce)
}

func ParseLinkDeviceRequest(message string) (*LinkDeviceRequest, error) {
	return ParseClientRequest(message, &LinkDeviceRequest{})
}

// response

type LinkDeviceResponse = ServerResponse[LinkDeviceResponsePayload]

type LinkDeviceResponsePayload struct{}

func NewLinkDeviceResponse(
	payload LinkDeviceResponsePayload,
	serverIdentity string,
	nonce string,
) *LinkDeviceResponse {
	return NewServerResponse(payload, serverIdentity, nonce)
}

func ParseLinkDeviceResponse(message string) (*LinkDeviceResponse, error) {
	return ParseServerResponse(message, &LinkDeviceResponse{})
}

type UnlinkDeviceRequest = ClientRequest[UnlinkDeviceRequestPayload]

type UnlinkDeviceRequestPayload struct {
	Authentication UnlinkDeviceRequestAuthentication `json:"authentication"`
	Link           UnlinkDeviceRequestLink           `json:"link"`
}

type UnlinkDeviceRequestAuthentication struct {
	Device       string `json:"device"`
	Identity     string `json:"identity"`
	PublicKey    string `json:"publicKey"`
	RotationHash string `json:"rotationHash"`
}

type UnlinkDeviceRequestLink struct {
	Device string `json:"device"`
}

func NewUnlinkDeviceRequest(payload UnlinkDeviceRequestPayload, nonce string) *UnlinkDeviceRequest {
	return NewClientRequest(payload, nonce)
}

func ParseUnlinkDeviceRequest(message string) (*UnlinkDeviceRequest, error) {
	return ParseClientRequest(message, &UnlinkDeviceRequest{})
}

// response

type UnlinkDeviceResponse = ServerResponse[UnlinkDeviceResponsePayload]

type UnlinkDeviceResponsePayload struct{}

func NewUnlinkDeviceResponse(
	payload UnlinkDeviceResponsePayload,
	serverIdentity string,
	nonce string,
) *UnlinkDeviceResponse {
	return NewServerResponse(payload, serverIdentity, nonce)
}

func ParseUnlinkDeviceResponse(message string) (*UnlinkDeviceResponse, error) {
	return ParseServerResponse(message, &UnlinkDeviceResponse{})
}
