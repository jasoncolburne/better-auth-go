package messages

type PublicKeys struct {
	Current    string `json:"current"`
	NextDigest string `json:"nextDigest"`
}

type Nonces struct {
	Current    *string `json:"current,omitempty"`
	NextDigest string  `json:"nextDigest"`
}
