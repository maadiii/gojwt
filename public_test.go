package gojwt

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func publicSignerConfig(t *testing.T, access, refresh rsaKeyPair) *PublicConfig {
	t.Helper()

	return &PublicConfig{
		Issuer:               testIssuer,
		Audience:             []string{testAudience},
		AccessPrivateKeyPath: writeTestFile(t, "access.key", access.privatePEM),
		RefreshPrivatePath:   writeTestFile(t, "refresh.key", refresh.privatePEM),
		AccessTtl:            accessTTL,
		RefreshTtl:           refreshTTL,
	}
}

func publicVerifierConfig(t *testing.T, access, refresh rsaKeyPair) *PublicConfig {
	t.Helper()

	return &PublicConfig{
		Issuer:               testIssuer,
		Audience:             []string{testAudience},
		AccessPublicKeyPath:  writeTestFile(t, "access.pub", access.publicPEM),
		RefreshPublicKeyPath: writeTestFile(t, "refresh.pub", refresh.publicPEM),
		AccessTtl:            accessTTL,
		RefreshTtl:           refreshTTL,
	}
}

func publicFullConfig(t *testing.T, access, refresh rsaKeyPair) *PublicConfig {
	t.Helper()

	return &PublicConfig{
		Issuer:               testIssuer,
		Audience:             []string{testAudience},
		AccessPrivateKeyPath: writeTestFile(t, "access.key", access.privatePEM),
		AccessPublicKeyPath:  writeTestFile(t, "access.pub", access.publicPEM),
		RefreshPrivatePath:   writeTestFile(t, "refresh.key", refresh.privatePEM),
		RefreshPublicKeyPath: writeTestFile(t, "refresh.pub", refresh.publicPEM),
		AccessTtl:            accessTTL,
		RefreshTtl:           refreshTTL,
	}
}

func mustPublicSig(t *testing.T, cfg *PublicConfig) *JwtPublic {
	t.Helper()

	j, err := NewPublicSig(cfg)
	if err != nil {
		t.Fatalf("NewPublicSig: %v", err)
	}

	return j
}

func mustPublicVer(t *testing.T, cfg *PublicConfig) *JwtPublic {
	t.Helper()

	j, err := NewPublicVer(cfg)
	if err != nil {
		t.Fatalf("NewPublicVer: %v", err)
	}

	return j
}

func TestNewPublicConstructorErrors(t *testing.T) {
	t.Parallel()

	access, refresh, _ := testKeyPairs(t)

	accessPrivatePath := writeTestFile(t, "access.key", access.privatePEM)
	refreshPrivatePath := writeTestFile(t, "refresh.key", refresh.privatePEM)
	accessPublicPath := writeTestFile(t, "access.pub", access.publicPEM)
	refreshPublicPath := writeTestFile(t, "refresh.pub", refresh.publicPEM)
	badKeyPath := writeTestFile(t, "bad.pem", []byte("not a pem encoded key"))
	missingPath := writeTestFile(t, "missing.pem", nil) + ".gone"

	tests := []struct {
		name string
		new  func(*PublicConfig) (*JwtPublic, error)
		cfg  *PublicConfig
	}{
		{
			name: "signer with " + nilConfigCase,
			new:  NewPublicSig,
		},
		{
			name: "signer without access private key path",
			new:  NewPublicSig,
			cfg:  &PublicConfig{RefreshPrivatePath: refreshPrivatePath},
		},
		{
			name: "signer without refresh private key path",
			new:  NewPublicSig,
			cfg:  &PublicConfig{AccessPrivateKeyPath: accessPrivatePath},
		},
		{
			name: "signer with unreadable access private key",
			new:  NewPublicSig,
			cfg: &PublicConfig{
				AccessPrivateKeyPath: missingPath,
				RefreshPrivatePath:   refreshPrivatePath,
			},
		},
		{
			name: "signer with invalid access private key",
			new:  NewPublicSig,
			cfg: &PublicConfig{
				AccessPrivateKeyPath: badKeyPath,
				RefreshPrivatePath:   refreshPrivatePath,
			},
		},
		{
			name: "signer with invalid refresh private key",
			new:  NewPublicSig,
			cfg: &PublicConfig{
				AccessPrivateKeyPath: accessPrivatePath,
				RefreshPrivatePath:   badKeyPath,
			},
		},
		{
			name: "signer with invalid access public key",
			new:  NewPublicSig,
			cfg: &PublicConfig{
				AccessPrivateKeyPath: accessPrivatePath,
				RefreshPrivatePath:   refreshPrivatePath,
				AccessPublicKeyPath:  badKeyPath,
			},
		},
		{
			name: "signer with invalid refresh public key",
			new:  NewPublicSig,
			cfg: &PublicConfig{
				AccessPrivateKeyPath: accessPrivatePath,
				RefreshPrivatePath:   refreshPrivatePath,
				RefreshPublicKeyPath: badKeyPath,
			},
		},
		{
			name: "verifier with " + nilConfigCase,
			new:  NewPublicVer,
		},
		{
			name: "verifier without access public key path",
			new:  NewPublicVer,
			cfg:  &PublicConfig{RefreshPublicKeyPath: refreshPublicPath},
		},
		{
			name: "verifier without refresh public key path",
			new:  NewPublicVer,
			cfg:  &PublicConfig{AccessPublicKeyPath: accessPublicPath},
		},
		{
			name: "verifier with unreadable access public key",
			new:  NewPublicVer,
			cfg: &PublicConfig{
				AccessPublicKeyPath:  missingPath,
				RefreshPublicKeyPath: refreshPublicPath,
			},
		},
		{
			name: "verifier with invalid access public key",
			new:  NewPublicVer,
			cfg: &PublicConfig{
				AccessPublicKeyPath:  badKeyPath,
				RefreshPublicKeyPath: refreshPublicPath,
			},
		},
		{
			name: "verifier with invalid refresh public key",
			new:  NewPublicVer,
			cfg: &PublicConfig{
				AccessPublicKeyPath:  accessPublicPath,
				RefreshPublicKeyPath: badKeyPath,
			},
		},
		{
			name: "verifier with invalid optional access private key",
			new:  NewPublicVer,
			cfg: &PublicConfig{
				AccessPublicKeyPath:  accessPublicPath,
				RefreshPublicKeyPath: refreshPublicPath,
				AccessPrivateKeyPath: badKeyPath,
			},
		},
		{
			name: "verifier with invalid optional refresh private key",
			new:  NewPublicVer,
			cfg: &PublicConfig{
				AccessPublicKeyPath:  accessPublicPath,
				RefreshPublicKeyPath: refreshPublicPath,
				RefreshPrivatePath:   badKeyPath,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if _, err := tc.new(tc.cfg); err == nil {
				t.Fatal("constructor error = nil, want error")
			}
		})
	}
}

func assertPublicConfigLoaded(t *testing.T, j *JwtPublic, cfg *PublicConfig) {
	t.Helper()

	if j.issuer != cfg.Issuer {
		t.Errorf("issuer = %q, want %q", j.issuer, cfg.Issuer)
	}
	if len(j.audience) != 1 || j.audience[0] != testAudience {
		t.Errorf("audience = %v, want [%q]", j.audience, testAudience)
	}
	if j.accessTtl != accessTTL {
		t.Errorf("accessTtl = %v, want %v", j.accessTtl, accessTTL)
	}
	if j.refreshTtl != refreshTTL {
		t.Errorf("refreshTtl = %v, want %v", j.refreshTtl, refreshTTL)
	}

	assertPublicKeysLoaded(t, j)
}

func assertPublicKeysLoaded(t *testing.T, j *JwtPublic) {
	t.Helper()

	if j.accessPrivateKey == nil || j.refreshPrivateKey == nil {
		t.Fatal("private keys were not loaded")
	}
	if j.accessPublicKey == nil || j.refreshPublicKey == nil {
		t.Fatal("public keys were not loaded")
	}
	if j.accessPrivateKey.N.Cmp(j.accessPublicKey.N) != 0 {
		t.Error("access key pair does not match")
	}
	if j.refreshPrivateKey.N.Cmp(j.refreshPublicKey.N) != 0 {
		t.Error("refresh key pair does not match")
	}
}

func TestNewPublicSigStoresConfig(t *testing.T) {
	t.Parallel()

	access, refresh, _ := testKeyPairs(t)
	cfg := publicFullConfig(t, access, refresh)

	assertPublicConfigLoaded(t, mustPublicSig(t, cfg), cfg)
}

func TestNewPublicVerStoresConfig(t *testing.T) {
	t.Parallel()

	access, refresh, _ := testKeyPairs(t)
	cfg := publicFullConfig(t, access, refresh)

	assertPublicConfigLoaded(t, mustPublicVer(t, cfg), cfg)
}

func TestJwtPublicGenerate(t *testing.T) {
	t.Parallel()

	access, refresh, _ := testKeyPairs(t)
	j := mustPublicSig(t, publicSignerConfig(t, access, refresh))

	tokens, err := j.Generate(context.Background(), testSubject, nil, nil)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	if tokens.Access == "" || tokens.Refresh == "" {
		t.Fatal("Generate() returned empty tokens")
	}
	if tokens.Access == tokens.Refresh {
		t.Fatal("access and refresh tokens are identical")
	}
}

func TestJwtPublicValidateAccess(t *testing.T) {
	t.Parallel()

	access, refresh, _ := testKeyPairs(t)
	j := mustPublicSig(t, publicFullConfig(t, access, refresh))
	before := time.Now().UTC()

	tokens, err := j.Generate(context.Background(), testSubject, map[string]any{testRoleKey: testAdminRole}, nil)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	claims, err := j.ValidateAccess(context.Background(), tokens.Access)
	if err != nil {
		t.Fatalf("ValidateAccess() error = %v", err)
	}

	assertRegisteredClaims(t, claims, testSubject, AccessTokenType)
	assertClaimTimes(t, claims, accessTTL)
	assertIssuedAfter(t, claims, before)

	if claims.CustomClaims[testRoleKey] != testAdminRole {
		t.Errorf("custom claims = %v", claims.CustomClaims)
	}
}

func TestJwtPublicValidateRefresh(t *testing.T) {
	t.Parallel()

	access, refresh, _ := testKeyPairs(t)
	j := mustPublicSig(t, publicFullConfig(t, access, refresh))

	tokens, err := j.Generate(context.Background(), testSubject, nil, map[string]any{testDeviceKey: testDeviceVal})
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	claims, err := j.ValidateRefresh(context.Background(), tokens.Refresh)
	if err != nil {
		t.Fatalf("ValidateRefresh() error = %v", err)
	}

	if claims.TokenType != RefreshTokenType {
		t.Errorf("token type = %q, want %q", claims.TokenType, RefreshTokenType)
	}
	if claims.CustomClaims[testDeviceKey] != testDeviceVal {
		t.Errorf("custom claims = %v", claims.CustomClaims)
	}
	if claims.ExpiresAt == nil || claims.IssuedAt == nil {
		t.Fatal("registered time claims are nil")
	}
	if claims.ExpiresAt.Sub(claims.IssuedAt.Time) != refreshTTL {
		t.Errorf("refresh lifetime = %v, want %v",
			claims.ExpiresAt.Sub(claims.IssuedAt.Time), refreshTTL)
	}
}

func TestJwtPublicSignerVerifierRoundTrip(t *testing.T) {
	t.Parallel()

	access, refresh, _ := testKeyPairs(t)

	signer := mustPublicSig(t, publicSignerConfig(t, access, refresh))
	verifier := mustPublicVer(t, publicVerifierConfig(t, access, refresh))

	tokens, err := signer.Generate(context.Background(), testSubject, map[string]any{testRoleKey: "user"}, nil)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	accessClaims, err := verifier.ValidateAccess(context.Background(), tokens.Access)
	if err != nil {
		t.Fatalf("ValidateAccess() error = %v", err)
	}

	assertRegisteredClaims(t, accessClaims, testSubject, AccessTokenType)

	if accessClaims.CustomClaims[testRoleKey] != "user" {
		t.Errorf("custom claims = %v", accessClaims.CustomClaims)
	}

	if _, err := verifier.ValidateRefresh(context.Background(), tokens.Refresh); err != nil {
		t.Fatalf("ValidateRefresh() error = %v", err)
	}
}

func TestJwtPublicValidateErrors(t *testing.T) {
	t.Parallel()

	access, refresh, other := testKeyPairs(t)

	signer := mustPublicSig(t, publicSignerConfig(t, access, refresh))
	verifier := mustPublicVer(t, publicVerifierConfig(t, access, refresh))

	tokens, err := signer.Generate(context.Background(), testSubject, nil, nil)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	wrongKeyVerifier := mustPublicVer(t, publicVerifierConfig(t, other, refresh))

	wrongIssuerCfg := publicVerifierConfig(t, access, refresh)
	wrongIssuerCfg.Issuer = "other-issuer"
	wrongIssuerVerifier := mustPublicVer(t, wrongIssuerCfg)

	wrongAudienceCfg := publicVerifierConfig(t, access, refresh)
	wrongAudienceCfg.Audience = []string{"other-audience"}
	wrongAudienceVerifier := mustPublicVer(t, wrongAudienceCfg)

	expiredCfg := publicSignerConfig(t, access, refresh)
	expiredCfg.AccessTtl = -time.Minute
	expiredCfg.RefreshTtl = -time.Minute
	expired := mustPublicSig(t, expiredCfg)

	expiredTokens, err := expired.Generate(context.Background(), testSubject, nil, nil)
	if err != nil {
		t.Fatalf("Generate() expired tokens error = %v", err)
	}

	hsToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, JwtClaims{
		Subject:   testSubject,
		Issuer:    testIssuer,
		Audience:  jwt.ClaimStrings{testAudience},
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute)),
		TokenType: AccessTokenType,
	}).SignedString([]byte("hs256-secret"))
	if err != nil {
		t.Fatalf("sign HS256 token: %v", err)
	}

	tests := []struct {
		name     string
		token    string
		validate func(context.Context, string) (*JwtClaims, error)
		wantIs   error
	}{
		{
			name:     "refresh token used as access",
			token:    tokens.Refresh,
			validate: verifier.ValidateAccess,
		},
		{
			name:     "access token used as refresh",
			token:    tokens.Access,
			validate: verifier.ValidateRefresh,
		},
		{
			name:     "tampered payload",
			token:    tamperPayload(t, tokens.Access),
			validate: verifier.ValidateAccess,
			wantIs:   jwt.ErrTokenSignatureInvalid,
		},
		{
			name:     "signed with another key",
			token:    tokens.Access,
			validate: wrongKeyVerifier.ValidateAccess,
			wantIs:   jwt.ErrTokenSignatureInvalid,
		},
		{
			name:     "unexpected issuer",
			token:    tokens.Access,
			validate: wrongIssuerVerifier.ValidateAccess,
			wantIs:   jwt.ErrTokenInvalidIssuer,
		},
		{
			name:     "unexpected audience",
			token:    tokens.Access,
			validate: wrongAudienceVerifier.ValidateAccess,
			wantIs:   jwt.ErrTokenInvalidAudience,
		},
		{
			name:     "expired access token",
			token:    expiredTokens.Access,
			validate: verifier.ValidateAccess,
			wantIs:   jwt.ErrTokenExpired,
		},
		{
			name:     "expired refresh token",
			token:    expiredTokens.Refresh,
			validate: verifier.ValidateRefresh,
			wantIs:   jwt.ErrTokenExpired,
		},
		{
			name:     "hs256 token rejected",
			token:    hsToken,
			validate: verifier.ValidateAccess,
		},
		{
			name:     "not a jwt",
			token:    "definitely-not-a-token",
			validate: verifier.ValidateAccess,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			claims, err := tc.validate(context.Background(), tc.token)
			if err == nil {
				t.Fatalf("validate() error = nil, claims = %+v", claims)
			}
			if tc.wantIs != nil && !errors.Is(err, tc.wantIs) {
				t.Errorf("validate() error = %v, want %v", err, tc.wantIs)
			}
		})
	}
}
