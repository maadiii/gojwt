package gojwt

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	accessTTL  = 15 * time.Minute
	refreshTTL = 24 * time.Hour
)

func localConfig() *LocalConfig {
	return &LocalConfig{
		Issuer:     testIssuer,
		Audience:   []string{testAudience},
		AccessKey:  []byte("test-access-key"),
		RefreshKey: []byte("test-refresh-key"),
		AccessTtl:  accessTTL,
		RefreshTtl: refreshTTL,
	}
}

func mustLocal(t *testing.T, cfg *LocalConfig) *JwtLocal {
	t.Helper()

	j, err := NewLocal(cfg)
	if err != nil {
		t.Fatalf("NewLocal: %v", err)
	}

	return j
}

func TestNewLocal(t *testing.T) {
	t.Parallel()

	emptyAccess := localConfig()
	emptyAccess.AccessKey = nil

	emptyRefresh := localConfig()
	emptyRefresh.RefreshKey = []byte{}

	tests := []struct {
		name string
		cfg  *LocalConfig
	}{
		{nilConfigCase, nil},
		{"empty access key", emptyAccess},
		{"empty refresh key", emptyRefresh},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if _, err := NewLocal(tc.cfg); err == nil {
				t.Fatal("NewLocal() error = nil, want error")
			}
		})
	}
}

func TestNewLocalStoresConfig(t *testing.T) {
	t.Parallel()

	cfg := localConfig()
	j := mustLocal(t, cfg)

	if j.issuer != cfg.Issuer {
		t.Errorf("issuer = %q, want %q", j.issuer, cfg.Issuer)
	}
	if len(j.audience) != len(cfg.Audience) || j.audience[0] != cfg.Audience[0] {
		t.Errorf("audience = %v, want %v", j.audience, cfg.Audience)
	}
	if string(j.accessKey) != string(cfg.AccessKey) {
		t.Errorf("accessKey = %q, want %q", j.accessKey, cfg.AccessKey)
	}
	if string(j.refreshKey) != string(cfg.RefreshKey) {
		t.Errorf("refreshKey = %q, want %q", j.refreshKey, cfg.RefreshKey)
	}
	if j.accessTtl != cfg.AccessTtl {
		t.Errorf("accessTtl = %v, want %v", j.accessTtl, cfg.AccessTtl)
	}
	if j.refreshTtl != cfg.RefreshTtl {
		t.Errorf("refreshTtl = %v, want %v", j.refreshTtl, cfg.RefreshTtl)
	}
}

func TestJwtLocalGenerate(t *testing.T) {
	t.Parallel()

	j := mustLocal(t, localConfig())

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

func TestJwtLocalValidateAccess(t *testing.T) {
	t.Parallel()

	j := mustLocal(t, localConfig())
	before := time.Now().UTC()

	tokens, err := j.Generate(
		context.Background(), testSubject,
		map[string]any{testRoleKey: testAdminRole, testTenantKey: testTenantVal},
		nil,
	)
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

	if claims.CustomClaims[testRoleKey] != testAdminRole ||
		claims.CustomClaims[testTenantKey] != testTenantVal {
		t.Errorf("custom claims = %v", claims.CustomClaims)
	}
}

func TestJwtLocalValidateRefresh(t *testing.T) {
	t.Parallel()

	j := mustLocal(t, localConfig())

	tokens, err := j.Generate(context.Background(), testSubject, nil, map[string]any{testDeviceKey: testDeviceVal})
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	claims, err := j.ValidateRefresh(context.Background(), tokens.Refresh)
	if err != nil {
		t.Fatalf("ValidateRefresh() error = %v", err)
	}

	if claims.Subject != testSubject {
		t.Errorf("subject = %q, want %q", claims.Subject, testSubject)
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

func TestJwtLocalGenerateWithoutCustomClaims(t *testing.T) {
	t.Parallel()

	j := mustLocal(t, localConfig())

	tokens, err := j.Generate(context.Background(), testSubject, nil, nil)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	access, err := j.ValidateAccess(context.Background(), tokens.Access)
	if err != nil {
		t.Fatalf("ValidateAccess() error = %v", err)
	}
	// CustomClaims is tagged omitempty, so an empty map is not serialized.
	if len(access.CustomClaims) != 0 {
		t.Errorf("CustomClaims = %v, want no custom claims", access.CustomClaims)
	}
}

// localDenyService adapts the shared deny-list cases to JwtLocal. The blocked
// check is wired to deniedFn and reports through onBlocked when a subject is
// rejected; nil hooks mean the service is built without deny handlers.
func localDenyService(
	t *testing.T, isBlocked func(string) (bool, error), onBlocked func(string),
) tokenService {
	t.Helper()

	cfg := localConfig()
	if isBlocked == nil {
		return mustLocal(t, cfg)
	}

	noopHook := func(context.Context, string) error { return nil }
	denied := func(_ context.Context, subject string) (bool, error) {
		blocked, err := isBlocked(subject)
		if err != nil {
			return false, err
		}
		if blocked && onBlocked != nil {
			onBlocked(subject)
		}

		return blocked, nil
	}

	j, err := NewLocalWithDenyHandler(cfg, noopHook, noopHook, denied)
	if err != nil {
		t.Fatalf("NewLocalWithDenyHandler: %v", err)
	}

	return j
}

func TestJwtLocalDenyList(t *testing.T) {
	t.Parallel()

	runDenyListTests(t, localDenyService)
}

func TestJwtLocalValidateErrors(t *testing.T) {
	t.Parallel()

	j := mustLocal(t, localConfig())

	tokens, err := j.Generate(context.Background(), testSubject, nil, nil)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	wrongIssuerCfg := localConfig()
	wrongIssuerCfg.Issuer = "other-issuer"
	wrongIssuer := mustLocal(t, wrongIssuerCfg)

	wrongAudienceCfg := localConfig()
	wrongAudienceCfg.Audience = []string{"other-audience"}
	wrongAudience := mustLocal(t, wrongAudienceCfg)

	wrongKeyCfg := localConfig()
	wrongKeyCfg.AccessKey = []byte("another-access-key")
	wrongAccessKey := mustLocal(t, wrongKeyCfg)

	expiredCfg := localConfig()
	expiredCfg.AccessTtl = -time.Minute
	expiredCfg.RefreshTtl = -time.Minute
	expired := mustLocal(t, expiredCfg)

	expiredTokens, err := expired.Generate(context.Background(), testSubject, nil, nil)
	if err != nil {
		t.Fatalf("Generate() expired tokens error = %v", err)
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
			validate: j.ValidateAccess,
		},
		{
			name:     "access token used as refresh",
			token:    tokens.Access,
			validate: j.ValidateRefresh,
		},
		{
			name:     "tampered payload",
			token:    tamperPayload(t, tokens.Access),
			validate: j.ValidateAccess,
			wantIs:   jwt.ErrTokenSignatureInvalid,
		},
		{
			name:     "signed with another key",
			token:    tokens.Access,
			validate: wrongAccessKey.ValidateAccess,
			wantIs:   jwt.ErrTokenSignatureInvalid,
		},
		{
			name:     "unexpected issuer",
			token:    tokens.Access,
			validate: wrongIssuer.ValidateAccess,
			wantIs:   jwt.ErrTokenInvalidIssuer,
		},
		{
			name:     "unexpected audience",
			token:    tokens.Access,
			validate: wrongAudience.ValidateAccess,
			wantIs:   jwt.ErrTokenInvalidAudience,
		},
		{
			name:     "expired access token",
			token:    expiredTokens.Access,
			validate: expired.ValidateAccess,
			wantIs:   jwt.ErrTokenExpired,
		},
		{
			name:     "expired refresh token",
			token:    expiredTokens.Refresh,
			validate: expired.ValidateRefresh,
			wantIs:   jwt.ErrTokenExpired,
		},
		{
			name:     "not a jwt",
			token:    "definitely-not-a-token",
			validate: j.ValidateAccess,
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
