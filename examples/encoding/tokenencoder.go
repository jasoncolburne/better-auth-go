package encoding

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"io"
)

type TokenEncoder[AttributesType any] struct{}

func NewTokenEncoder[AttributesType any]() *TokenEncoder[AttributesType] {
	return &TokenEncoder[AttributesType]{}
}

func (*TokenEncoder[AttributesType]) Encode(object string) (string, error) {
	var compressedBuffer bytes.Buffer
	writer, err := gzip.NewWriterLevel(&compressedBuffer, 9)
	if err != nil {
		return "", err
	}

	if _, err := writer.Write([]byte(object)); err != nil {
		return "", err
	}

	if err := writer.Close(); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(compressedBuffer.Bytes()), nil
}

func (*TokenEncoder[AttributesType]) Decode(token string) (string, error) {
	gzippedToken, err := base64.RawURLEncoding.DecodeString(token) // TODO remove magic
	if err != nil {
		return "", err
	}

	compressedBuffer := bytes.NewBuffer(gzippedToken)
	reader, err := gzip.NewReader(compressedBuffer)
	if err != nil {
		return "", err
	}

	bytes, err := io.ReadAll(reader)
	if err != nil {
		return "", err
	}

	if err := reader.Close(); err != nil {
		return "", err
	}

	return string(bytes), nil
}
