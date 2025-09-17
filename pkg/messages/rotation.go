package messages

// ```json
// {
//     "payload": {
//         "identification": {
//             "accountId": "ENBRKI-MIlE-m8h5SY-kLOzmzGhCvovugIvRyXYbrXC3",
//             "deviceId": "EAWkUfWVAMzIDy4aHjWwBwaQrmScYMpFobT93Ct6RVv_"
//         },
//         "authentication": {
//             "publicKeys": {
//                 "current": "1AAIA7CUSQ_Cvk3XE1ITDNQXS1qpdqEKwCk4q5Q4YP7GtuIq",
//                 "nextDigest": "EEool9L2Vj-c30J8b0v-yThCVpxIJ5dAXPQSnge3IzvG"
//             }
//         }
//     },
//     "signature": "0IAZBlyJEQu-gmS05iYOfUhrDU3NV5Q5E_9PsYF0s5y-QHc5t4j0Rvh-0ljHVcGrt3VL3gB6qodEHDmiZNOhOg2Q"
// }
// ```

type RotateAuthenticationKeyRequest struct {
	Payload   RotateAuthenticationKeyRequestPayload `json:"payload"`
	Signature string                                `json:"signature"`
}

type RotateAuthenticationKeyRequestPayload struct {
	Identification RotateAuthenticationKeyRequestIdentification `json:"identification"`
	Authentication RotateAuthenticationKeyRequestAuthentication `json:"authentication"`
}

type RotateAuthenticationKeyRequestIdentification struct {
	AccountId string `json:"accountId"`
	DeviceId  string `json:"deviceId"`
}

type RotateAuthenticationKeyRequestAuthentication struct {
	PublicKeys PublicKeys `json:"publicKeys"`
}

// ```json
// {
//     "payload": {
//         "success": true,
//         "publicKeyDigest": "EPqXgqZ_AiTVBfY2l_-vW016GroHLhLkeYrNc4HQB7WO"
//     },
//     "signature": "0IBcQqawkcFHuUgogsnh8tyKqBWnDLY6tbvLVAfw5aE9VxSEx0CQ_A5ILLgnlDX8vrl3X35xi6-p-ytUK5GVLie5"
// }
// ```

type RotateAuthenticationKeyResponse struct {
	Payload   RotateAuthenticationKeyResponsePayload `json:"payload"`
	Signature string                                 `json:"signature"`
}

type RotateAuthenticationKeyResponsePayload struct {
	Success         bool `json:"success"`
	PublicKeyDigest string
}
