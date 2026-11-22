package gojwt

import (
	"context"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrDeniedSubject = errors.New("subject is denied")
	ErrInvalidToken  = errors.New("invalid token")
	ErrInvalidClaims = errors.New("invalid claims")
)

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

type (
	denyFn   func(ctx context.Context, subject string) error
	undenyFn func(ctx context.Context, subject string) error
	deniedFn func(ctx context.Context, subject string) (bool, error)
)
