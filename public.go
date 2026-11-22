package gojwt

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"maps"
	"os"
	"time"
	"uuid"

	"github.com/golang-jwt/jwt/v5"
)

type JwtPublic struct {
	issuer            string
	audience          []string
	accessPrivateKey  *rsa.PrivateKey
	accessPublicKey   *rsa.PublicKey
	refreshPrivateKey *rsa.PrivateKey
	refreshPublicKey  *rsa.PublicKey
	accessTtl         time.Duration
	refreshTtl        time.Duration

	denyFn   denyFn
	undenyFn undenyFn
	deniedFn deniedFn
}

// NewPublicSig construc *JwtPublic to sign the token in the signature side.
func NewPublicSig(cfg *PublicConfig) (*JwtPublic, error) { //nolint
	if cfg == nil || cfg.AccessPrivateKeyPath == "" || cfg.RefreshPrivatePath == "" {
		return nil, errors.New("private key paths are required")
	}

	accPrivKey, err := loadPrivateKey(cfg.AccessPrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	refPrivKey, err := loadPrivateKey(cfg.RefreshPrivatePath)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	jwtPublic := &JwtPublic{
		issuer:            cfg.Issuer,
		audience:          cfg.Audience,
		accessPrivateKey:  accPrivKey,
		refreshPrivateKey: refPrivKey,
		accessTtl:         cfg.AccessTtl,
		refreshTtl:        cfg.RefreshTtl,
	}

	if cfg.AccessPublicKeyPath != "" {
		jwtPublic.accessPublicKey, err = loadPublicKey(cfg.AccessPublicKeyPath)
		if err != nil {
			return nil, fmt.Errorf("%w", err)
		}
	}

	if cfg.RefreshPublicKeyPath != "" {
		jwtPublic.refreshPublicKey, err = loadPublicKey(cfg.RefreshPublicKeyPath)
		if err != nil {
			return nil, fmt.Errorf("%w", err)
		}
	}

	return jwtPublic, nil
}

// NewPublicSigWithDenyHandler construc *JwtPublic to sign the token in the signature side with deny handlers.
func NewPublicSigWithDenyHandler(
	cfg *PublicConfig, denyFn denyFn, undenyFn undenyFn, deniedFn deniedFn,
) (*JwtPublic, error) {
	if denyFn == nil || undenyFn == nil || deniedFn == nil {
		return nil, errors.New("denyFn, undenyFn and deniedFn all must be set")
	}

	jwt, err := NewPublicSig(cfg)
	if err != nil {
		return nil, err
	}

	jwt.denyFn = denyFn
	jwt.undenyFn = undenyFn
	jwt.deniedFn = deniedFn

	return jwt, nil
}

// NewPublicVer construct *JwtPublic to verify the token in the verifier side.
func NewPublicVer(cfg *PublicConfig) (*JwtPublic, error) { //nolint
	if cfg == nil || cfg.AccessPublicKeyPath == "" || cfg.RefreshPublicKeyPath == "" {
		return nil, errors.New("public key paths are required")
	}

	accPubKey, err := loadPublicKey(cfg.AccessPublicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	refPubKey, err := loadPublicKey(cfg.RefreshPublicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	jwtPublic := &JwtPublic{
		issuer:           cfg.Issuer,
		audience:         cfg.Audience,
		accessPublicKey:  accPubKey,
		refreshPublicKey: refPubKey,
		accessTtl:        cfg.AccessTtl,
		refreshTtl:       cfg.RefreshTtl,
	}

	if cfg.AccessPrivateKeyPath != "" {
		jwtPublic.accessPrivateKey, err = loadPrivateKey(cfg.AccessPrivateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("%w", err)
		}
	}

	if cfg.RefreshPrivatePath != "" {
		jwtPublic.refreshPrivateKey, err = loadPrivateKey(cfg.RefreshPrivatePath)
		if err != nil {
			return nil, fmt.Errorf("%w", err)
		}
	}

	return jwtPublic, nil
}

// NewPublicVerWithDenyHandler construc *JwtPublic to verify the token in the verifier side with deny handlers.
func NewPublicVerWithDenyHandler(
	cfg *PublicConfig, denyFn denyFn, undenyFn undenyFn, deniedFn deniedFn,
) (*JwtPublic, error) {
	if denyFn == nil || undenyFn == nil || deniedFn == nil {
		return nil, errors.New("jwt: denyFn, undenyFn and deniedFn all must be set")
	}

	jwt, err := NewPublicVer(cfg)
	if err != nil {
		return nil, err
	}

	jwt.denyFn = denyFn
	jwt.undenyFn = undenyFn
	jwt.deniedFn = deniedFn

	return jwt, nil
}

func (j *JwtPublic) Generate(
	ctx context.Context, subject string, accessCustomeClaims map[string]any, refreshCustomeClaims map[string]any,
) (*Tokens, error) {
	denied, err := j.deniedFn(ctx, subject)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}
	if denied {
		return nil, ErrDeniedSubject
	}

	access, err := j.makeToken(subject, AccessTokenType, j.accessTtl, j.accessPrivateKey, accessCustomeClaims)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	refresh, err := j.makeToken(subject, RefreshTokenType, j.refreshTtl, j.refreshPrivateKey, refreshCustomeClaims)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	return &Tokens{
		Access:  access,
		Refresh: refresh,
	}, nil
}

func (j *JwtPublic) ValidateAccess(ctx context.Context, signed string) (*JwtClaims, error) {
	return j.validate(ctx, signed, AccessTokenType, j.accessPublicKey)
}

func (j *JwtPublic) ValidateRefresh(ctx context.Context, signed string) (*JwtClaims, error) {
	return j.validate(ctx, signed, RefreshTokenType, j.refreshPublicKey)
}

func (j *JwtPublic) makeToken(
	subject string, typ TokenType, ttl time.Duration,
	privateKey *rsa.PrivateKey, customClaims map[string]any,
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

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, err := token.SignedString(privateKey)
	if err != nil {
		return "", err
	}

	return signed, nil
}

func (j *JwtPublic) validate(
	ctx context.Context, signed string, expected TokenType, publicKey *rsa.PublicKey,
) (*JwtClaims, error) {
	parsedClaims := JwtClaims{}
	token, err := jwt.ParseWithClaims(
		signed, &parsedClaims, func(t *jwt.Token) (any, error) {
			if t.Method.Alg() != jwt.SigningMethodRS256.Alg() {
				return nil, errors.New("unexpected signing method")
			}

			return publicKey, nil
		},
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
		jwt.WithIssuer(j.issuer),
		jwt.WithAudience(j.audience...),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	if !token.Valid {
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*JwtClaims)
	if !ok {
		return nil, ErrInvalidClaims
	}

	if claims.TokenType != expected {
		return nil, ErrInvalidToken
	}

	denied, err := j.deniedFn(ctx, claims.Subject)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}
	if denied {
		return nil, ErrDeniedSubject
	}

	return claims, nil
}

func (j *JwtPublic) Deny(ctx context.Context, subject string) error {
	return j.denyFn(ctx, subject)
}

func (j *JwtPublic) Undeny(ctx context.Context, subject string) error {
	return j.undenyFn(ctx, subject)
}

func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return jwt.ParseRSAPrivateKeyFromPEM(data)
}

func loadPublicKey(path string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return jwt.ParseRSAPublicKeyFromPEM(data)
}
