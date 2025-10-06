package encodinginterfaces

type TokenEncoder interface {
	Encode(object string) (string, error)
	Decode(token string) (string, error)
	SignatureLength(token string) (int, error)
}
