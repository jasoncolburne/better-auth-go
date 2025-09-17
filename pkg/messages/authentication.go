package messages

// ```json
// {
//     "identification": {
//         "accountId": "ENBRKI-MIlE-m8h5SY-kLOzmzGhCvovugIvRyXYbrXC3"
//     }
// }
// ```

type BeginAuthenticationRequest struct {
	Payload BeginAuthenticationRequestPayload `json:"payload"`
}

type BeginAuthenticationRequestPayload struct {
	Identification BeginAuthenticationRequestIdentification `json:"identification"`
}

type BeginAuthenticationRequestIdentification struct {
	AccountId string `json:"accountId"`
}

// ```json
// {
//     "payload": {
//         "authentication": {
//             "nonce": "0ADSOF85vtKb4QQTIy319M4j"
//         },
//         "publicKeyDigest": "EPqXgqZ_AiTVBfY2l_-vW016GroHLhLkeYrNc4HQB7WO"
//     },
//     "signature": "0IAUi8wD3zLlDzqyG3uB9-jsIpzOXGKqrVSO8UcGpNx8d9E_VZzaM4oovT6Mjqs_edso78MnXpzjTItwdva6zwTZ"
// }
// ```

type BeginAuthenticationResponse struct {
	Payload   BeginAuthenticationResponsePayload `json:"payload"`
	Signature string                             `json:"signature"`
}

type BeginAuthenticationResponsePayload struct {
	Authentication  BeginAuthenticationResponseAuthentication `json:"authentication"`
	PublicKeyDigest string                                    `json:"publicKeyDigest"`
}

type BeginAuthenticationResponseAuthentication struct {
	Nonce string `json:"nonce"`
}

// ```json
// {
//     "payload": {
//         "identification": {
//             "deviceId": "EAWkUfWVAMzIDy4aHjWwBwaQrmScYMpFobT93Ct6RVv_"
//         },
//         "authentication": {
//             "nonce": "0ADSOF85vtKb4QQTIy319M4j"
//         },
//         "refresh": {
//             "publicKey": "1AAIArseHqu34sgRTFelYKd342JUZ1TeJnNMk2xE9NjvtXrD",
//             "nonces": {
//                 "nextDigest": "EC1Hc4KgIsAm7Azif1lxv0HoxhKL_T0UPtQ8ZgeEu1wF"
//             }
//         }
//     },
//     "signature": "0IAbiRvVF7Zb7-FVL29VuOE9kR2KezCjCreaYqMjc2okbd7ZPsVTpHbpZVdXeyIjM0KM-f9iykvMyIg3jYkBjobU"
// }
// ```

type CompleteAuthenticationRequest struct {
	Payload   CompleteAuthenticationRequestPayload `json:"payload"`
	Signature string                               `json:"signature"`
}

type CompleteAuthenticationRequestPayload struct {
	Identification CompleteAuthenticationRequestIdentification `json:"identification"`
	Authentication CompleteAuthenticationRequestAuthentication `json:"authentication"`
	Refresh        CompleteAuthenticationRequestRefresh        `json:"refresh"`
}

type CompleteAuthenticationRequestIdentification struct {
	DeviceId string `json:"deviceId"`
}

type CompleteAuthenticationRequestAuthentication struct {
	Nonce string `json:"nonce"`
}

type CompleteAuthenticationRequestRefresh struct {
	PublicKey string `json:"publicKey"`
	Nonces    Nonces `json:"nonces"`
}

// ```json
// {
//     "payload": {
//         "refresh": {
//             "sessionId": "EMP0iq5tvNJlIOQoRla5Qa_s7P4X9pzY-50smblRfrw9"
//         },
//         "publicKeyDigest": "EPqXgqZ_AiTVBfY2l_-vW016GroHLhLkeYrNc4HQB7WO"
//     },
//     "signature": "0IDLl5gh1G7KYsRK0LAVx4CMqAMeK_q_nUzHnYOxxj7aXidXQPoC1gt5dm3yDvEmqHiFG-keLLmyDwfHEGitl41Q"
// }
// ```

type CompleteAuthenticationResponse struct {
	Payload   CompleteAuthenticationResponsePayload `json:"payload"`
	Signature string                                `json:"signature"`
}

type CompleteAuthenticationResponsePayload struct {
	Refresh         CompleteAuthenticationResponseRefresh `json:"refresh"`
	PublicKeyDigest string                                `json:"publicKeyDigest"`
}

type CompleteAuthenticationResponseRefresh struct {
	SessionId string `json:"sessionId"`
}

// ```json
// {
//     "identification": {
//         "accountId": "ENBRKI-MIlE-m8h5SY-kLOzmzGhCvovugIvRyXYbrXC3"
//     }
// }
// ```

type BeginPassphraseAuthenticationRequest struct {
	Payload BeginPassphraseAuthenticationRequestPayload `json:"payload"`
}

type BeginPassphraseAuthenticationRequestPayload struct {
	Identification BeginPassphraseAuthenticationRequestIdentification `json:"identification"`
}

type BeginPassphraseAuthenticationRequestIdentification struct {
	AccountId string `json:"accountId"`
}

// ```json
// {
//     "payload": {
//         "passphraseAuthentication": {
//             "nonce": "0ADSOF85vtKb4QQTIy319M4j",
//             "parameters": "$argon2id$v=19$m=262144,t=3,p=4$",
//             "salt": "0AEbin7spiwkRaXks8K5AA9x"
//         },
//         "publicKeyDigest": "EPqXgqZ_AiTVBfY2l_-vW016GroHLhLkeYrNc4HQB7WO"
//     },
//     "signature": "0IDk7TGXAnU_6aqhZPO7yOROlDLhwzElJXvm2d0qJS-qFCRdwDnstxy6ttJyogxKz4IQxUaZaweQc9wvHbbWdJWG"
// }
// ```

type BeginPassphraseAuthenticationResponse struct {
	Payload   BeginPassphraseAuthenticationResponsePayload `json:"payload"`
	Signature string                                       `json:"signature"`
}

type BeginPassphraseAuthenticationResponsePayload struct {
	PassphraseAuthentication BeginPassphraseAuthenticationResponsePassphraseAuthentication `json:"passphraseAuthentication"`
	PublicKeyDigest          string                                                        `json:"publicKeyDigest"`
}

type BeginPassphraseAuthenticationResponsePassphraseAuthentication struct {
	Nonce      string `json:"nonce"`
	Parameters string `json:"parameters"`
	Salt       string `json:"salt"`
}

// ```json
// {
//     "payload": {
//         "passphraseAuthentication": {
//             "nonce": "0ADSOF85vtKb4QQTIy319M4j",
//             "publicKey": "BOFIM_iwIwrZO3mPxjOqkwTvRfmvNjBQQqrGxk_ncS61"
//         },
//         "refresh": {
//             "publicKey": "1AAIArseHqu34sgRTFelYKd342JUZ1TeJnNMk2xE9NjvtXrD",
//             "nonces": {
//                 "nextDigest": "EC1Hc4KgIsAm7Azif1lxv0HoxhKL_T0UPtQ8ZgeEu1wF"
//             }
//         }
//     },
//     "signature": "0BD1WQsuqNXG4wBTalLpwLYxdz3xgtjF05aBcg3ZoFzaDsfqPpobEE2s9fJjHIRMAhhGCpCRsfpC4i1jjNdkrROK"
// }
// ```

type CompletePassphraseAuthenticationRequest struct {
	Payload   CompletePassphraseAuthenticationRequestPayload `json:"payload"`
	Signature string                                         `json:"signature"`
}

type CompletePassphraseAuthenticationRequestPayload struct {
	PassphraseAuthentication CompletePassphraseAuthenticationRequestPassphraseAuthentication `json:"passphraseAuthentication"`
	Refresh                  CompletePassphraseAuthenticationRequestRefresh                  `json:"refresh"`
}

type CompletePassphraseAuthenticationRequestPassphraseAuthentication struct {
	Nonce     string `json:"nonce"`
	PublicKey string `json:"publicKey"`
}

type CompletePassphraseAuthenticationRequestRefresh struct {
	PublicKey string `json:"publicKey"`
	Nonces    Nonces `json:"nonces"`
}

// ```json
// {
//     "payload": {
//         "refresh": {
//             "sessionId": "EMP0iq5tvNJlIOQoRla5Qa_s7P4X9pzY-50smblRfrw9"
//         },
//         "publicKeyDigest": "EPqXgqZ_AiTVBfY2l_-vW016GroHLhLkeYrNc4HQB7WO"
//     },
//     "signature": "0IBnIffOKisy1nd63tMdupzmpcpRQJjER7plDCgcxPrRPPjggi6JDIRIB7zzFg--rlNBqdBg0dcBtQtFhRwcaMxD"
// }
// ```

type CompletePassphraseAuthenticationResponse struct {
	Payload   CompletePassphraseAuthenticationResponsePayload `json:"payload"`
	Signature string                                          `json:"signature"`
}

type CompletePassphraseAuthenticationResponsePayload struct {
	Refresh         CompletePassphraseAuthenticationResponseRefresh `json:"refresh"`
	PublicKeyDigest string                                          `json:"publicKeyDigest"`
}

type CompletePassphraseAuthenticationResponseRefresh struct {
	SessionId string `json:"sessionId"`
}
