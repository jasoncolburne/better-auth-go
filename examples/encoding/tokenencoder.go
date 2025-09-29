package encoding

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"io"
)

type TokenEncoder[T any] struct{}

func NewTokenEncoder[T any]() *TokenEncoder[T] {
	return &TokenEncoder[T]{}
}

func (*TokenEncoder[T]) Encode(object string) (string, error) {
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

func (*TokenEncoder[T]) Decode(token string) (string, error) {
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
