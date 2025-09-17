package messages

// ```json
// {
//     "payload": {
//         "registration": {
//             "token": "EOomXwkCWQXvmAHc96c8e1_PF4BGsvWvsMHU6XsP3Zmj"
//         },
//         "publicKeyDigest": "EPqXgqZ_AiTVBfY2l_-vW016GroHLhLkeYrNc4HQB7WO"
//     },
//     "signature": "0ICXhZ4M_41TLsp6iMoRyOuWFil9UL7SYY5AcZjx993uNGM1jUXGAxaFg730FJ8sfe0glEPRiTR3ihF2cxjz_61z"
// }
// ```

type RegistrationMaterials struct {
	Payload   RegistrationMaterialsPayload `json:"payload"`
	Signature string                       `json:"signature"`
}

type RegistrationMaterialsPayload struct {
	Registration    RegistrationMaterialsRegistration `json:"registration"`
	PublicKeyDigest string                            `json:"publicKeyDigest"`
}

type RegistrationMaterialsRegistration struct {
	Token string `json:"token"`
}

// ```json
// {
//     "payload": {
//         "registration": {
//             "token": "EOomXwkCWQXvmAHc96c8e1_PF4BGsvWvsMHU6XsP3Zmj"
//         },
//         "passphraseAuthentication": {
//             "parameters": "$argon2id$v=19$m=262144,t=3,p=4$",
//             "salt": "0AEbin7spiwkRaXks8K5AA9x"
//         },
//         "publicKeyDigest": "EPqXgqZ_AiTVBfY2l_-vW016GroHLhLkeYrNc4HQB7WO"
//     },
//     "signature": "0IBKAxkerhXG0hER9Oll5DmyoT-LFkzTST9dfBieHngP7HYtc6fgzYncdaSXLfCM4eTu20QNHmLCqrw7Rb_jzpHX"
// }
// ```

type PassphraseRegistrationMaterials struct {
	Payload   PassphraseRegistrationMaterialsPayload `json:"payload"`
	Signature string                                 `json:"signature"`
}

type PassphraseRegistrationMaterialsPayload struct {
	Registration             PassphraseRegistrationMaterialsRegistration             `json:"registration"`
	PassphraseAuthentication PassphraseRegistrationMaterialsPassphraseAuthentication `json:"passphraseAuthentication"`
	PublicKeyDigest          string                                                  `json:"publicKeyDigest"`
}

type PassphraseRegistrationMaterialsRegistration struct {
	Token string `json:"token"`
}

type PassphraseRegistrationMaterialsPassphraseAuthentication struct {
	Parameters string `json:"parameters"`
	Salt       string `json:"salt"`
}

// ```json
// {
//     "payload": {
//         "registration": {
//             "token": "EOomXwkCWQXvmAHc96c8e1_PF4BGsvWvsMHU6XsP3Zmj"
//         },
//         "identification": {
//             "deviceId": "EAWkUfWVAMzIDy4aHjWwBwaQrmScYMpFobT93Ct6RVv_"
//         },
//         "authentication": {
//             "publicKeys": {
//                 "current": "1AAIAl-5-nkK7Jp4d1svQnxCEnpuCtwny5Eri4D2n_edfNZf",
//                 "nextDigest": "ECGWcxYw1bNzyEbuvsnVBnZTTyDDWfwfL_pcyNLawM8O"
//             }
//         }
//     },
//     "signature": "0IAIuRf6J9w677nb8NV4OXlXcq9xGFUakaRPLiY4Hmlhmn87GfiNZGO_thFVfzJVRLe6D04DFZj3MdzhTwb463lD"
// }
// ```

type RegisterAuthenticationKeyRequest struct {
	Payload   RegisterAuthenticationKeyRequestPayload `json:"payload"`
	Signature string                                  `json:"signature"`
}

type RegisterAuthenticationKeyRequestPayload struct {
	Registration   RegisterAuthenticationKeyRequestRegistration   `json:"registration"`
	Identification RegisterAuthenticationKeyRequestIdentification `json:"identification"`
	Authentication RegisterAuthenticationKeyRequestAuthentication `json:"authentication"`
}

type RegisterAuthenticationKeyRequestRegistration struct {
	Token string `json:"token"`
}

type RegisterAuthenticationKeyRequestIdentification struct {
	DeviceId string `json:"deviceId"`
}

type RegisterAuthenticationKeyRequestAuthentication struct {
	PublicKeys PublicKeys `json:"publicKeys"`
}

// ```json
// {
//     "payload": {
//         "identification": {
//             "accountId": "ENBRKI-MIlE-m8h5SY-kLOzmzGhCvovugIvRyXYbrXC3"
//         },
//         "publicKeyDigest": "EPqXgqZ_AiTVBfY2l_-vW016GroHLhLkeYrNc4HQB7WO"
//     },
//     "signature": "0ICXhZ4M_41TLsp6iMoRyOuWFil9UL7SYY5AcZjx993uNGM1jUXGAxaFg730FJ8sfe0glEPRiTR3ihF2cxjz_61z"
// }
// ```

type RegisterAuthenticationKeyResponse struct {
	Payload   RegisterAuthenticationKeyResponsePayload `json:"payload"`
	Signature string                                   `json:"signature"`
}

type RegisterAuthenticationKeyResponsePayload struct {
	Identification  RegisterAuthenticationKeyResponseIdentification `json:"identification"`
	PublicKeyDigest string                                          `json:"publicKeyDigest"`
}

type RegisterAuthenticationKeyResponseIdentification struct {
	AccountId string `json:"accountId"`
}

// ```json
// {
//     "payload": {
//         "registration": {
//             "token": "EOomXwkCWQXvmAHc96c8e1_PF4BGsvWvsMHU6XsP3Zmj"
//         },
//         "passphraseAuthentication": {
//             "publicKey": "BOFIM_iwIwrZO3mPxjOqkwTvRfmvNjBQQqrGxk_ncS61"
//         }
//     },
//     "signature": "0BAsKeUTSuvSUJdBsofjGaEmAFtvbaX0YJgyNZS7MCWAkzWA99wIkjgB41FQrcrCd1LgxIULtk7rz2vKDeYkBEIy"
// }
// ```

type RegisterPassphraseAuthenticationKeyRequest struct {
	Payload   RegisterPassphraseAuthenticationKeyRequestPayload `json:"payload"`
	Signature string                                            `json:"signature"`
}

type RegisterPassphraseAuthenticationKeyRequestPayload struct {
	Registration             RegisterPassphraseAuthenticationKeyRequestRegistration             `json:"registration"`
	PassphraseAuthentication RegisterPassphraseAuthenticationKeyRequestPassphraseAuthentication `json:"passphraseAuthentication"`
}

type RegisterPassphraseAuthenticationKeyRequestRegistration struct {
	Token string `json:"token"`
}

type RegisterPassphraseAuthenticationKeyRequestPassphraseAuthentication struct {
	PublicKey string `json:"publicKey"`
}

// ```json
// {
//     "payload": {
//         "identification": {
//             "accountId": "ENBRKI-MIlE-m8h5SY-kLOzmzGhCvovugIvRyXYbrXC3"
//         },
//         "publicKeyDigest": "EPqXgqZ_AiTVBfY2l_-vW016GroHLhLkeYrNc4HQB7WO"
//     },
//     "signature": "0IAsstrWmV_cpbtS0niO7-xUWrR_YtXrqjAQlkhPv4X66qOohd_FfdKC58WggJil1RvTsv9z4F0S-VWkoogzrML7"
// }
// ```

type RegisterPassphraseAuthenticationKeyResponse struct {
	Payload   RegisterPassphraseAuthenticationKeyResponsePayload `json:"payload"`
	Signature string                                             `json:"signature"`
}

type RegisterPassphraseAuthenticationKeyResponsePayload struct {
	Identification  RegisterPassphraseAuthenticationKeyResponseIdentification `json:"identification"`
	PublicKeyDigest string                                                    `json:"publicKeyDigest"`
}

type RegisterPassphraseAuthenticationKeyResponseIdentification struct {
	AccountId string `json:"accountId"`
}
