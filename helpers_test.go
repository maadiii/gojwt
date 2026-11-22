package gojwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testIssuer   = "test-issuer"
	testAudience = "test-audience"

	testSubject     = "user-1"
	testRoleKey     = "role"
	testAdminRole   = "admin"
	testTenantKey   = "tenant"
	testTenantVal   = "acme"
	testDeviceKey   = "device"
	testDeviceVal   = "laptop"
	testBlockedUser = "blocked-user"

	nilConfigCase = "nil config"

	rsaKeyBits  = 2048
	testFileMod = 0o600
	tokenParts  = 3
)

type rsaKeyPair struct {
	privatePEM []byte
	publicPEM  []byte
}

var (
	keyPairsOnce sync.Once
	keyPairs     [3]rsaKeyPair
	keyPairsErr  error
)

// testKeyPairs returns an access key pair, a refresh key pair and an unrelated
// pair used to check that tokens signed with a different key are rejected.
func testKeyPairs(t *testing.T) (rsaKeyPair, rsaKeyPair, rsaKeyPair) {
	t.Helper()

	keyPairsOnce.Do(func() {
		for i := range keyPairs {
			keyPairs[i], keyPairsErr = generateRSAKeyPair()
			if keyPairsErr != nil {
				return
			}
		}
	})
	if keyPairsErr != nil {
		t.Fatalf("generate RSA key pairs: %v", keyPairsErr)
	}

	return keyPairs[0], keyPairs[1], keyPairs[2]
}

func generateRSAKeyPair() (rsaKeyPair, error) {
	key, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		return rsaKeyPair{}, err
	}

	publicDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return rsaKeyPair{}, err
	}

	return rsaKeyPair{
		privatePEM: pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		}),
		publicPEM: pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: publicDER,
		}),
	}, nil
}

func writeTestFile(t *testing.T, name string, data []byte) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, testFileMod); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}

	return path
}

func assertRegisteredClaims(t *testing.T, claims *JwtClaims, subject string, typ TokenType) {
	t.Helper()

	if claims.Subject != subject {
		t.Errorf("subject = %q, want %q", claims.Subject, subject)
	}
	if claims.Issuer != testIssuer {
		t.Errorf("issuer = %q, want %q", claims.Issuer, testIssuer)
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != testAudience {
		t.Errorf("audience = %v, want [%q]", claims.Audience, testAudience)
	}
	if claims.TokenType != typ {
		t.Errorf("token type = %q, want %q", claims.TokenType, typ)
	}
	if claims.ID == "" {
		t.Error("token ID is empty")
	}
}

func assertClaimTimes(t *testing.T, claims *JwtClaims, ttl time.Duration) {
	t.Helper()

	if claims.IssuedAt == nil || claims.ExpiresAt == nil || claims.NotBefore == nil {
		t.Fatal("registered time claims are nil")
	}

	issued := claims.IssuedAt.Time
	expires := claims.ExpiresAt.Time

	if got := expires.Sub(issued); got != ttl {
		t.Errorf("token lifetime = %v, want %v", got, ttl)
	}
}

func assertIssuedAfter(t *testing.T, claims *JwtClaims, earliest time.Time) {
	t.Helper()

	if claims.IssuedAt == nil {
		t.Fatal("issued at claim is nil")
	}

	// NumericDate truncates to whole seconds, so allow up to one second of
	// skew against a sub-second test start time.
	issued := claims.IssuedAt.Time
	if issued.Before(earliest.Add(-time.Second)) {
		t.Errorf("issued at %v is before %v", issued, earliest)
	}
}

type tokenService interface {
	Generate(subject string, accessClaims, refreshClaims map[string]any) (*Tokens, error)
	ValidateAccess(signed string) (*JwtClaims, error)
	ValidateRefresh(signed string) (*JwtClaims, error)
}

// runDenyListTests exercises the deny list contract shared by both
// implementations. newService must apply the supplied hooks to its config.
func runDenyListTests(
	t *testing.T,
	newService func(isBlocked func(string) (bool, error), onBlocked func(string)) tokenService,
) {
	t.Helper()

	testDenyListDecisions(t, newService)
	testDenyListFailures(t, newService)
}

func testDenyListDecisions(
	t *testing.T,
	newService func(isBlocked func(string) (bool, error), onBlocked func(string)) tokenService,
) {
	t.Helper()

	t.Run("allows subject that is not blocked", func(t *testing.T) {
		t.Parallel()

		var events []string
		svc := newService(
			func(subject string) (bool, error) { return subject == testBlockedUser, nil },
			func(subject string) { events = append(events, subject) },
		)

		tokens := mustGenerate(t, svc, testSubject)
		if _, err := svc.ValidateAccess(tokens.Access); err != nil {
			t.Fatalf("ValidateAccess() error = %v", err)
		}
		if _, err := svc.ValidateRefresh(tokens.Refresh); err != nil {
			t.Fatalf("ValidateRefresh() error = %v", err)
		}
		if len(events) != 0 {
			t.Errorf("events = %v, want none", events)
		}
	})

	t.Run("denies blocked tokens and emits the event", func(t *testing.T) {
		t.Parallel()

		var events []string
		svc := newService(
			func(subject string) (bool, error) { return subject == testBlockedUser, nil },
			func(subject string) { events = append(events, subject) },
		)

		tokens := mustGenerate(t, svc, testBlockedUser)

		if _, err := svc.ValidateAccess(tokens.Access); !errors.Is(err, ErrDeniedSubject) {
			t.Errorf("ValidateAccess() error = %v, want %v", err, ErrDeniedSubject)
		}
		if _, err := svc.ValidateRefresh(tokens.Refresh); !errors.Is(err, ErrDeniedSubject) {
			t.Errorf("ValidateRefresh() error = %v, want %v", err, ErrDeniedSubject)
		}

		want := []string{testBlockedUser, testBlockedUser}
		if len(events) != len(want) || events[0] != want[0] || events[1] != want[1] {
			t.Errorf("events = %v, want %v", events, want)
		}
	})
}

func testDenyListFailures(
	t *testing.T,
	newService func(isBlocked func(string) (bool, error), onBlocked func(string)) tokenService,
) {
	t.Helper()

	t.Run("propagates deny list errors", func(t *testing.T) {
		t.Parallel()

		denyErr := errors.New("deny list unavailable")
		var events []string
		svc := newService(
			func(string) (bool, error) { return false, denyErr },
			func(subject string) { events = append(events, subject) },
		)

		tokens := mustGenerate(t, svc, testSubject)

		_, err := svc.ValidateAccess(tokens.Access)
		if !errors.Is(err, denyErr) {
			t.Errorf("ValidateAccess() error = %v, want %v", err, denyErr)
		}
		if errors.Is(err, ErrDeniedSubject) {
			t.Errorf("ValidateAccess() error = %v, want no %v", err, ErrDeniedSubject)
		}
		if len(events) != 0 {
			t.Errorf("events = %v, want none", events)
		}
	})

	t.Run("does not emit the event for unverified tokens", func(t *testing.T) {
		t.Parallel()

		var events []string
		svc := newService(
			func(string) (bool, error) { return true, nil },
			func(subject string) { events = append(events, subject) },
		)

		_, err := svc.ValidateAccess("definitely-not-a-token")
		if err == nil {
			t.Fatal("ValidateAccess() error = nil, want error")
		}
		if errors.Is(err, ErrDeniedSubject) {
			t.Errorf("ValidateAccess() error = %v, want no %v", err, ErrDeniedSubject)
		}
		if len(events) != 0 {
			t.Errorf("events = %v, want none", events)
		}
	})

	t.Run("accepts tokens without a deny list hook", func(t *testing.T) {
		t.Parallel()

		svc := newService(nil, nil)

		tokens := mustGenerate(t, svc, testBlockedUser)
		if _, err := svc.ValidateAccess(tokens.Access); err != nil {
			t.Fatalf("ValidateAccess() error = %v", err)
		}
	})
}

func mustGenerate(t *testing.T, svc tokenService, subject string) *Tokens {
	t.Helper()

	tokens, err := svc.Generate(subject, nil, nil)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	return tokens
}

// tamperPayload re-encodes the token payload with a modified subject while
// leaving the original signature in place.
func tamperPayload(t *testing.T, token string) string {
	t.Helper()

	parts := strings.Split(token, ".")
	if len(parts) != tokenParts {
		t.Fatalf("expected %d token parts, got %d", tokenParts, len(parts))
	}

	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}

	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}

	claims["sub"] = "attacker"

	tampered, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	parts[1] = base64.RawURLEncoding.EncodeToString(tampered)

	return strings.Join(parts, ".")
}
