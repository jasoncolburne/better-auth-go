package accesstoken

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/jasoncolburne/better-auth-go/pkg/messages"
)

func Encode(token *messages.AccessToken, signature string) (string, error) {
	var compressedBuffer bytes.Buffer

	gzipWriter := gzip.NewWriter(&compressedBuffer)
	encoder := json.NewEncoder(gzipWriter)

	err := encoder.Encode(token)
	if err != nil {
		return "", err
	}

	err = gzipWriter.Close()
	if err != nil {
		return "", err
	}

	bytes := compressedBuffer.Bytes()

	output := fmt.Sprintf("%s%s", signature, base64.RawURLEncoding.EncodeToString(bytes))

	return output, nil
}

func Decode(encodedToken string) (*messages.AccessToken, string, error) {
	signature := encodedToken[:88] // TODO remove magic

	encodedString := encodedToken[88:]
	for len(encodedString)%4 != 0 {
		encodedString = encodedString + "="
	}

	gzippedToken, err := base64.URLEncoding.DecodeString(encodedString) // TODO remove magic
	if err != nil {
		return nil, "", err
	}

	compressedBuffer := bytes.NewBuffer(gzippedToken)
	gzipReader, err := gzip.NewReader(compressedBuffer)
	if err != nil {
		return nil, "", err
	}

	decoder := json.NewDecoder(gzipReader)

	token := &messages.AccessToken{}

	if err := decoder.Decode(token); err != nil {
		return nil, "", err
	}

	fmt.Printf("%v\n", token)

	if err := gzipReader.Close(); err != nil {
		return nil, "", err
	}

	return token, signature, nil
}
