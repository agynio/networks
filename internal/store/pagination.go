package store

import (
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

const (
	DefaultListPageSize int32 = 50
	MaxListPageSize     int32 = 100
)

type PageCursor struct {
	AfterID uuid.UUID
}

func NormalizePageSize(size int32) int32 {
	if size <= 0 {
		return DefaultListPageSize
	}
	if size > MaxListPageSize {
		return MaxListPageSize
	}
	return size
}

func EncodePageToken(id uuid.UUID) string {
	return base64.RawURLEncoding.EncodeToString([]byte(id.String()))
}

func DecodePageToken(token string) (uuid.UUID, error) {
	if token == "" {
		return uuid.UUID{}, errors.New("empty token")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return uuid.UUID{}, fmt.Errorf("decode token: %w", err)
	}
	value, err := uuid.Parse(string(decoded))
	if err != nil {
		return uuid.UUID{}, fmt.Errorf("parse token: %w", err)
	}
	return value, nil
}
