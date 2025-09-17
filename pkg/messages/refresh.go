package messages

import orderedmap "github.com/wk8/go-ordered-map/v2"

// ```json
// {
//     "payload": {
//         "refresh": {
//             "sessionId": "EMP0iq5tvNJlIOQoRla5Qa_s7P4X9pzY-50smblRfrw9",
//             "nonces": {
//                 "current": "0AhfUcHYwHdfn69sF9HqdGg-",
//                 "nextDigest": "EJ6cZ-LKxUNyuS6mZKyydY6JOBhpHaFnf34AYtudnMRV",
//             }
//         },
//         "access": {
//             "publicKey": "1AAIA7UjnxSVGI1gabpe9W6fU7yK7VUL5u3TFu7nI2D03DPH"
//         }
//     },
//     "signature": "0IB8dO5R5L5Y27HQGtzxhi1SyXX_mjRR-SLP35KkzywiMygFOHDJf27DMh8O1UOIwpGwHWqhejE-wGj1oE7JHPAQ"
// }
// ```

type RefreshAccessTokenRequest struct {
	Payload   RefreshAccessTokenRequestPayload `json:"payload"`
	Signature string                           `json:"signature"`
}

type RefreshAccessTokenRequestPayload struct {
	Refresh RefreshAccessTokenRequestRefresh `json:"refresh"`
	Access  RefreshAccessTokenRequestAccess  `json:"access"`
}

type RefreshAccessTokenRequestRefresh struct {
	SessionId string `json:"sessionId"`
	Nonces    Nonces `json:"nonces"`
}

type RefreshAccessTokenRequestAccess struct {
	PublicKey string `json:"publicKey"`
}

// ```json
// {
//     "payload": {
//         "access": {
//             "token": ""
// 		   },
//         "publicKeyDigest": "EPqXgqZ_AiTVBfY2l_-vW016GroHLhLkeYrNc4HQB7WO"
//     },
//     "signature": "0ICRa_DmuiriwY3e-_rURIgLVrXbytXNS7wzh4aLT-ViouI4OLAhBglwnifxJCR0KMqIDj53suTomaa8OszhtBtM"
// }
// ```

type RefreshAccessTokenResponse struct {
	Payload   RefreshAccessTokenResponsePayload `json:"payload"`
	Signature string                            `json:"signature"`
}

type RefreshAccessTokenResponsePayload struct {
	Access          RefreshAccessTokenResponseAccess `json:"access"`
	PublicKeyDigest string                           `json:"publicKeyDigest"`
}

type RefreshAccessTokenResponseAccess struct {
	Token string `json:"token"`
}

//         {
//             "token": {
//                 "accountId": "ENBRKI-MIlE-m8h5SY-kLOzmzGhCvovugIvRyXYbrXC3"
//                 "publicKey": "1AAIA7UjnxSVGI1gabpe9W6fU7yK7VUL5u3TFu7nI2D03DPH",
//                 "issuedAt": "2025-09-15T09:10:00Z",
//                 "expiry": "2025-09-15T09:25:00Z",
//                 "attributes": {
//                     "label": "value"
//                 }
//             },
//             "signature": "0ICqCbTD10ciOuNZGzjxySGs46xhJF39MLGHx09UEFljxvArv7YoDss3OhUYj7T4l0oR9yElrk0eSlqSiXwG6KZ7"
//         }

type AccessToken struct {
	AccountId  string                              `json:"accountId"`
	PublicKey  string                              `json:"publicKey"`
	IssuedAt   string                              `json:"issuedAt"`
	Expiry     string                              `json:"expiry"`
	Attributes *orderedmap.OrderedMap[string, any] `json:"attributes,omitempty"`
}
