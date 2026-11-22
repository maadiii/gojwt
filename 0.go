package gojwt

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ErrSubjectBlocked is returned when a valid token belongs to a subject that
// the caller's deny list rejects.
var ErrSubjectBlocked = errors.New("jwt: subject is blocked")

type JwtClaims struct {
	jwt.RegisteredClaims
	TokenType    TokenType      `json:"typ,omitempty"`
	CustomClaims map[string]any `json:"customClaims,omitempty"`
}

type LocalConfig struct {
	Issuer     string
	Audience   []string
	AccessKey  []byte
	RefreshKey []byte
	AccessTtl  time.Duration
	RefreshTtl time.Duration
}

type PublicConfig struct {
	Issuer               string
	Audience             []string
	AccessPrivateKeyPath string
	AccessPublicKeyPath  string
	RefreshPrivatePath   string
	RefreshPublicKeyPath string
	AccessTtl            time.Duration
	RefreshTtl           time.Duration

	// IsBlockFn reports whether a subject is on the caller's deny list.
	// It runs after a token has been verified. Optional.
	IsBlockFn func(subject string) (bool, error)
	// OnBlocked is an event invoked whenever a verified token is rejected
	// because its subject is denied. Optional.
	OnBlocked func(subject string)
}

type Tokens struct {
	Access  string
	Refresh string
}

type TokenType string

const (
	AccessTokenType  TokenType = "access"
	RefreshTokenType TokenType = "refresh"
)
