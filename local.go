package gojwt

import (
	"errors"
	"fmt"
	"maps"
	"time"
	"uuid"

	"github.com/golang-jwt/jwt/v5"
)

type JwtLocal struct {
	issuer     string
	audience   []string
	accessKey  []byte
	refreshKey []byte
	accessTtl  time.Duration
	refreshTtl time.Duration
}

func NewLocal(cfg *LocalConfig) (*JwtLocal, error) {
	if cfg == nil || len(cfg.AccessKey) == 0 || len(cfg.RefreshKey) == 0 {
		return nil, fmt.Errorf("jwt keys cannot be empty")
	}

	return &JwtLocal{
		issuer:     cfg.Issuer,
		audience:   cfg.Audience,
		accessKey:  cfg.AccessKey,
		refreshKey: cfg.RefreshKey,
		accessTtl:  cfg.AccessTtl,
		refreshTtl: cfg.RefreshTtl,
	}, nil
}

func (j JwtLocal) Generate(
	subject string, accessCustomClaims map[string]any, refreshCustomeClaims map[string]any,
) (*Tokens, error) {
	access, err := j.makeToken(subject, AccessTokenType, j.accessTtl, j.accessKey, accessCustomClaims)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	refresh, err := j.makeToken(subject, RefreshTokenType, j.refreshTtl, j.refreshKey, refreshCustomeClaims)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	return &Tokens{access, refresh}, nil
}

func (j JwtLocal) ValidateAccess(signed string) (*JwtClaims, error) {
	return j.validate(signed, AccessTokenType, j.accessKey)
}

func (j JwtLocal) ValidateRefresh(signed string) (*JwtClaims, error) {
	return j.validate(signed, RefreshTokenType, j.refreshKey)
}

func (j JwtLocal) makeToken(
	subject string, typ TokenType, ttl time.Duration,
	key []byte, customClaims map[string]any,
) (string, error) {
	now := time.Now().UTC()
	exp := now.Add(ttl)

	claims := JwtClaims{
		ID:           uuid.NewV7().String(),
		Subject:      subject,
		Audience:     j.audience,
		Issuer:       j.issuer,
		IssuedAt:     jwt.NewNumericDate(now),
		ExpiresAt:    jwt.NewNumericDate(exp),
		NotBefore:    jwt.NewNumericDate(now),
		TokenType:    typ,
		CustomClaims: make(map[string]any),
	}

	maps.Copy(claims.CustomClaims, customClaims)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(key)
	if err != nil {
		return "", err
	}

	return signed, nil
}

func (j JwtLocal) validate(signed string, expected TokenType, key []byte) (*JwtClaims, error) {
	localClaims := JwtClaims{}
	token, err := jwt.ParseWithClaims(
		signed, &localClaims, func(t *jwt.Token) (any, error) {
			if t.Method.Alg() != jwt.SigningMethodHS256.Name {
				return nil, errors.New("unexpcted signing method")
			}

			return key, nil
		},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(j.issuer),
		jwt.WithAudience(j.audience...),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	claims, ok := token.Claims.(*JwtClaims)
	if !ok {
		return nil, errors.New("invalid claims")
	}

	if localClaims.TokenType != expected {
		return nil, errors.New("invalid token")
	}

	return claims, nil
}
