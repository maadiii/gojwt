# gojwt

`gojwt` is a small, opinionated JWT helper for issuing and validating access and
refresh token pairs in Go. It wraps [`github.com/golang-jwt/jwt/v5`](https://github.com/golang-jwt/jwt)
and handles the repetitive parts for you: paired token generation, separate
access/refresh signing keys, token-type enforcement, issuer/audience checks,
required expiry, UUIDv7 token IDs, custom claims, and an optional deny list.

Two implementations are provided:

| Type        | Signing algorithm | Keys                                     | Use case                              |
|-------------|-------------------|------------------------------------------|---------------------------------------|
| `JwtLocal`  | `HS256`           | Shared secrets (`[]byte`)                | Single service or trusted environment |
| `JwtPublic` | `RS256`           | RSA private/public keys loaded from PEM  | Separate issuer and verifier services |

- [Installation](#installation)
- [Quick start: symmetric keys](#quick-start-symmetric-keys)
- [Quick start: RSA keys](#quick-start-rsa-keys)
- [Configuration](#configuration)
- [Generating tokens](#generating-tokens)
- [Validating tokens](#validating-tokens)
- [Claims](#claims)
- [Deny handlers](#deny-handlers)
- [Errors](#errors)
- [Behavior and guarantees](#behavior-and-guarantees)
- [Testing](#testing)
- [Security notes](#security-notes)

## Installation

```bash
go get github.com/maadiii/gojwt
```

The module targets Go 1.27.1 and depends on `github.com/golang-jwt/jwt/v5`
(v5.3.1), which is vendored in this repository.

## Quick start: symmetric keys

```go
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/maadiii/gojwt"
)

func main() {
	auth, err := gojwt.NewLocal(&gojwt.LocalConfig{
		Issuer:     "my-service",
		Audience:   []string{"my-api"},
		AccessKey:  []byte("a-long-random-access-secret"),
		RefreshKey: []byte("a-different-random-refresh-secret"),
		AccessTtl:  15 * time.Minute,
		RefreshTtl: 24 * time.Hour,
	})
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()

	tokens, err := auth.Generate(
		ctx,
		"user-123",
		map[string]any{"role": "admin"},   // access-token custom claims
		map[string]any{"device": "laptop"}, // refresh-token custom claims
	)
	if err != nil {
		log.Fatal(err)
	}

	claims, err := auth.ValidateAccess(ctx, tokens.Access)
	switch {
	case errors.Is(err, gojwt.ErrDeniedSubject):
		log.Fatal("subject is blocked")
	case err != nil:
		log.Fatal(err)
	}

	fmt.Println(claims.Subject, claims.TokenType)
	if role, ok := claims.CustomClaims["role"]; ok {
		fmt.Println("role:", role)
	}

	// Later, when the access token expires, validate the refresh token.
	if _, err := auth.ValidateRefresh(ctx, tokens.Refresh); err != nil {
		log.Fatal(err)
	}
}
```

## Quick start: RSA keys

Use separate RSA key pairs for access and refresh tokens. The signing side only
needs the private keys and the verifying side only needs the public keys.

Generate keys with OpenSSL:

```bash
# Access token key pair
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out access.key
openssl rsa -pubout -in access.key -out access.pub

# Refresh token key pair
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out refresh.key
openssl rsa -pubout -in refresh.key -out refresh.pub
```

Signing side:

```go
signer, err := gojwt.NewPublicSig(&gojwt.PublicConfig{
	Issuer:               "auth-service",
	Audience:             []string{"my-api"},
	AccessPrivateKeyPath: "access.key",
	RefreshPrivatePath:   "refresh.key",
	AccessTtl:            15 * time.Minute,
	RefreshTtl:           24 * time.Hour,
})
if err != nil {
	log.Fatal(err)
}

tokens, err := signer.Generate(ctx, "user-123", accessClaims, refreshClaims)
```

Verifying side:

```go
verifier, err := gojwt.NewPublicVer(&gojwt.PublicConfig{
	Issuer:               "auth-service",
	Audience:             []string{"my-api"},
	AccessPublicKeyPath:  "access.pub",
	RefreshPublicKeyPath: "refresh.pub",
})
if err != nil {
	log.Fatal(err)
}

claims, err := verifier.ValidateAccess(ctx, tokens.Access)
```

A service that both signs and verifies can use `PublicConfig` with all four key
paths and either constructor; each constructor optionally loads the extra keys
when the corresponding paths are set.

Keys must be PEM encoded. Private keys may be PKCS#1 or PKCS#8. Public keys may
be PKIX, PKCS#1, or a PEM-encoded certificate.

## Configuration

### `LocalConfig`

| Field        | Type            | Required | Description                                     |
|--------------|-----------------|----------|-------------------------------------------------|
| `Issuer`     | `string`        | Yes*     | Value written to and required from the `iss` claim. |
| `Audience`   | `[]string`      | Yes*     | Values written to and required from the `aud` claim. |
| `AccessKey`  | `[]byte`        | Yes      | HMAC secret used to sign and verify access tokens. |
| `RefreshKey` | `[]byte`        | Yes      | HMAC secret used to sign and verify refresh tokens. |
| `AccessTtl`  | `time.Duration` | Yes*     | Lifetime of access tokens. |
| `RefreshTtl` | `time.Duration` | Yes*     | Lifetime of refresh tokens. |

\* Required for correct validation. `NewLocal` only rejects a nil config and
empty access/refresh keys; set an issuer, a non-empty audience, and positive
TTLs.

### `PublicConfig`

| Field                   | Type            | Required for signer | Required for verifier | Description |
|-------------------------|-----------------|---------------------|-----------------------|-------------|
| `Issuer`                | `string`        | Yes*                | Yes*                  | `iss` claim value and expected issuer. |
| `Audience`              | `[]string`      | Yes*                | Yes*                  | `aud` claim values and expected audience. |
| `AccessPrivateKeyPath`  | `string`        | Yes                 | No                    | PEM RSA private key for access tokens. |
| `AccessPublicKeyPath`   | `string`        | No                  | Yes                   | PEM RSA public key for access tokens. |
| `RefreshPrivatePath`    | `string`        | Yes                 | No                    | PEM RSA private key for refresh tokens. |
| `RefreshPublicKeyPath`  | `string`        | No                  | Yes                   | PEM RSA public key for refresh tokens. |
| `AccessTtl`             | `time.Duration` | Yes*                | No                    | Access token lifetime. |
| `RefreshTtl`            | `time.Duration` | Yes*                | No                    | Refresh token lifetime. |

\* Required for correct validation.

Constructors:

- `NewLocal(cfg *LocalConfig) (*JwtLocal, error)`
- `NewLocalWithDenyHandler(cfg *LocalConfig, denyFn, undenyFn, deniedFn) (*JwtLocal, error)`
- `NewPublicSig(cfg *PublicConfig) (*JwtPublic, error)` — loads the access and
  refresh private keys; optionally loads public keys.
- `NewPublicSigWithDenyHandler(cfg, denyFn, undenyFn, deniedFn) (*JwtPublic, error)`
- `NewPublicVer(cfg *PublicConfig) (*JwtPublic, error)` — loads the access and
  refresh public keys; optionally loads private keys.
- `NewPublicVerWithDenyHandler(cfg, denyFn, undenyFn, deniedFn) (*JwtPublic, error)`

The `WithDenyHandler` constructors require all three hooks to be non-nil.

## Generating tokens

```go
func (j *JwtLocal) Generate(
	ctx context.Context,
	subject string,
	accessCustomClaims map[string]any,
	refreshCustomClaims map[string]any,
) (*Tokens, error)
```

`JwtPublic` exposes the same method. It signs two tokens with the configured
access and refresh keys/TTLs and returns:

```go
type Tokens struct {
	Access  string
	Refresh string
}
```

Both tokens share the same subject and registered claims but have independent
custom claims, lifetimes, signing keys, and `typ` values (`access` / `refresh`).
Passing `nil` for a custom-claims map is allowed; the token then has no custom
claims.

Generation does not consult the deny list. Denial is enforced when a token is
validated, so a subject blocked after issuance can no longer refresh or use
tokens.

## Validating tokens

```go
func (j *JwtLocal) ValidateAccess(ctx context.Context, signed string) (*JwtClaims, error)
func (j *JwtLocal) ValidateRefresh(ctx context.Context, signed string) (*JwtClaims, error)
```

`JwtPublic` exposes the same methods. Validation performs all of the following:

1. Parses and verifies the signature with the matching access or refresh key.
2. Allows only the implementation's algorithm (`HS256` for local, `RS256` for
   public) and rejects tokens signed with any other algorithm.
3. Requires `exp`, rejects expired tokens, and validates `nbf` when present.
   `iat` is not verified (the `jwt/v5` default), and no clock skew/leeway is
   configured.
4. Requires the configured `iss` and, when a non-empty audience is configured,
   the `aud` values.
5. Requires the token's `typ` claim to match the method called: an access token
   is rejected by `ValidateRefresh` and vice versa.
6. Calls the configured `deniedFn` hook, if any, and returns
   `ErrDeniedSubject` when the subject is blocked.

## Claims

Every token uses `JwtClaims`:

```go
type JwtClaims struct {
	jwt.RegisteredClaims
	TokenType    TokenType      `json:"typ,omitempty"`
	CustomClaims map[string]any `json:"customClaims,omitempty"`
}
```

Registered claims populated on generation:

| Claim | Value |
|-------|-------|
| `iss` | Configured issuer |
| `aud` | Configured audience list |
| `sub` | Subject passed to `Generate` |
| `iat` | Issue time (UTC) |
| `nbf` | Issue time (UTC) |
| `exp` | Issue time + configured TTL |
| `jti` | UUIDv7 string |

Token types:

```go
const (
	AccessTokenType  TokenType = "access"
	RefreshTokenType TokenType = "refresh"
)
```

Custom claims are stored under the `customClaims` JSON key rather than being
flattened into the top-level claims. Access and refresh tokens can carry
different custom claims.

## Deny handlers

A deny list can be attached at construction so blocked subjects cannot use
previously issued tokens:

```go
auth, err := gojwt.NewLocalWithDenyHandler(
	cfg,
	func(ctx context.Context, subject string) error {
		return denyList.Add(ctx, subject)
	},
	func(ctx context.Context, subject string) error {
		return denyList.Remove(ctx, subject)
	},
	func(ctx context.Context, subject string) (bool, error) {
		return denyList.Contains(ctx, subject)
	},
)
if err != nil {
	log.Fatal(err)
}

if err := auth.Deny(ctx, "user-123"); err != nil {
	log.Fatal(err)
}
if err := auth.Undeny(ctx, "user-123"); err != nil {
	log.Fatal(err)
}
```

The same functions are available on `JwtPublic`.

- `Deny(ctx, subject)` calls the stored `denyFn`.
- `Undeny(ctx, subject)` calls the stored `undenyFn`.
- `ValidateAccess` / `ValidateRefresh` call the stored `deniedFn`.
- If validation finds the subject blocked, it returns `ErrDeniedSubject`.
- If a hook returns an error, validation wraps and returns it.
- Services built without handlers skip the deny check entirely. `Deny` and
  `Undeny` require handlers to have been configured and will panic when called
  on a service constructed without them.

Hooks are invoked synchronously and may be called concurrently by multiple
validations, so any backing store must be safe for concurrent use.

## Errors

| Error              | Meaning |
|--------------------|---------|
| `ErrDeniedSubject` | The token is otherwise valid, but the subject is on the deny list. |
| `ErrInvalidToken`  | The parsed token is invalid or has the wrong token type. |
| `ErrInvalidClaims` | The parsed claims are not `*JwtClaims`. |

Signing, parsing, signature, issuer, audience, and expiry failures from
`jwt/v5` are wrapped with `%w`, so `errors.Is` works with sentinel errors such
as `jwt.ErrTokenExpired`, `jwt.ErrTokenSignatureInvalid`,
`jwt.ErrTokenInvalidIssuer`, and `jwt.ErrTokenInvalidAudience`.

Constructor errors are returned for missing config, missing required key paths,
unreadable files, and invalid PEM keys.

## Behavior and guarantees

- Access and refresh tokens always use different signing keys when configured
  that way; neither can be validated through the other's method even if the
  same key material is reused.
- `Generate` returns the tokens in a `Tokens` value; no persistence, rotation,
  or reuse tracking is performed.
- There is no `kid` header, key rotation, revocation list storage, or clock-skew
  configuration built in. Revocation is supported only through deny handlers.
- `JwtLocal` and `JwtPublic` are stateless after construction and safe for
  concurrent use, provided any custom deny hooks are safe as well.
- Custom claim values must be JSON-serializable.

## Testing

```bash
go test ./...
go test -race ./...
```

The test suite covers constructors, key loading failures, generation,
validation, signer/verifier round trips, wrong-key and wrong-algorithm
rejection, issuer/audience/expiry failures, token-type confusion, tampering, and
the deny-list contract for both implementations.

## Security notes

- Use long, random, distinct secrets for `AccessKey` and `RefreshKey`. Do not
  reuse a secret across access and refresh tokens or across environments.
- Use RSA keys of at least 2048 bits and keep private keys out of source
  control and logs.
- Always set `Issuer`, a non-empty `Audience`, and positive TTLs; validation
  requires `exp` but cannot protect against a zero or negative TTL chosen at
  signing time.
- Treat refresh tokens as sensitive credentials: store them securely on the
  client and validate them before issuing a new token pair.
