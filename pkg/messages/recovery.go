package messages

// request

type ChangeRecoveryKeyRequest = ClientRequest[ChangeRecoveryKeyRequestPayload]

type ChangeRecoveryKeyRequestPayload struct {
	Authentication ChangeRecoveryKeyRequestAuthentication `json:"authentication"`
}

type ChangeRecoveryKeyRequestAuthentication struct {
	Device       string `json:"device"`
	Identity     string `json:"identity"`
	PublicKey    string `json:"publicKey"`
	RecoveryHash string `json:"recoveryHash"`
	RotationHash string `json:"rotationHash"`
}

func NewChangeRecoveryKeyRequest(payload ChangeRecoveryKeyRequestPayload, nonce string) *ChangeRecoveryKeyRequest {
	return NewClientRequest(payload, nonce)
}

func ParseChangeRecoveryKeyRequest(message string) (*ChangeRecoveryKeyRequest, error) {
	return ParseClientRequest(message, &ChangeRecoveryKeyRequest{})
}

// response

type ChangeRecoveryKeyResponse = ServerResponse[ChangeRecoveryKeyResponsePayload]

type ChangeRecoveryKeyResponsePayload struct{}

func NewChangeRecoveryKeyResponse(
	payload ChangeRecoveryKeyResponsePayload,
	serverIdentity string,
	nonce string,
) *ChangeRecoveryKeyResponse {
	return NewServerResponse(payload, serverIdentity, nonce)
}

func ParseChangeRecoveryKeyResponse(message string) (*ChangeRecoveryKeyResponse, error) {
	return ParseServerResponse(message, &ChangeRecoveryKeyResponse{})
}
