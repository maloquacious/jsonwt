# How to use jsonwt

These recipes assume you have completed the [tutorial](tutorial.md) and need
the shortest supported procedure for a specific task. They use this local-only
factory helper:

```go
func newFactory(keyID, secret string) *jsonwt.Factory {
	signer, err := signers.NewHS256([]byte(secret))
	if err != nil {
		panic(err)
	}
	return jsonwt.NewFactory(keyID, signer)
}
```

Complete versions of these recipes are exercised as executable examples in
[`howto_test.go`](../howto_test.go). Use `jsonwt` only for the non-production
environments described in [Security and scope](security.md).

## Issue and read custom application claims

**Goal:** round-trip application-specific JSON through a signed token.

**Prerequisites:** the factory helper above and a claim shape whose exported
fields can be encoded as JSON.

Define a JSON-marshalable type, issue the token, and parse it before reading
the claim:

```go
type sessionClaim struct {
	User string   `json:"user"`
	Tags []string `json:"tags"`
}

factory := newFactory("local-key", "local-demo-secret-change-me")
issued, err := factory.Token(10*time.Minute, sessionClaim{
	User: "ada",
	Tags: []string{"reader", "tester"},
})
if err != nil {
	panic(err)
}

parsed, err := factory.Parse(issued.String())
if err != nil {
	panic(err)
}
var claim sessionClaim
if err := parsed.Claim(&claim); err != nil {
	panic(err)
}
fmt.Println(claim.User, claim.Tags)
```

The result is `ada [reader tester]`. Pass a pointer to `Claim` so JSON can
populate it. See the [`Factory.Token`, `Factory.Parse`, and `Token.Claim`
reference](https://pkg.go.dev/github.com/mdhender/jsonwt#Factory) and the
[security boundaries](security.md).

## Send and read a bearer token with net/http

**Goal:** put a token in an HTTP request and safely consume it in a handler.

**Prerequisites:** a configured factory shared by the local sender and handler,
plus `net/http` and `net/http/httptest`.

Set the standard authorization header on the client side. On the server side,
extract the token, then validate it with the expected factory before using it:

```go
issued, err := factory.Token(10*time.Minute, sessionClaim{User: "ada"})
if err != nil {
	panic(err)
}

request := httptest.NewRequest(http.MethodGet, "/profile", nil)
request.Header.Set("Authorization", "Bearer "+issued.String())

received := jsonwt.FromBearerToken(request)
if received == nil {
	panic("missing bearer token")
}
if err := factory.Validate(received); err != nil {
	panic(err)
}
fmt.Println(received.IsValid())
```

`FromBearerToken` only decodes the header; it does not establish trust.
Validation is therefore mandatory before reading claims. The result is `true`.
See the
[`FromBearerToken` reference](https://pkg.go.dev/github.com/mdhender/jsonwt#FromBearerToken)
and the [security boundaries](security.md).

## Set, read, and delete the package cookie

**Goal:** round-trip a token through the package-owned HTTP cookie and then
remove it.

**Prerequisites:** a configured factory and `net/http/httptest`.

Use `httptest` recorders and requests in tests; the same calls work with an
`http.ResponseWriter` and `*http.Request` in a handler:

```go
issued, err := factory.Token(10*time.Minute, sessionClaim{User: "ada"})
if err != nil {
	panic(err)
}

response := httptest.NewRecorder()
issued.SetCookie(response)
cookie := response.Result().Cookies()[0]

request := httptest.NewRequest(http.MethodGet, "/profile", nil)
request.AddCookie(cookie)
received := jsonwt.FromCookie(request)
if received == nil {
	panic("missing token cookie")
}
if err := factory.Validate(received); err != nil {
	panic(err)
}

response = httptest.NewRecorder()
jsonwt.DeleteCookie(response)
deleted := response.Result().Cookies()[0]
fmt.Println(cookie.Name, cookie.HttpOnly, deleted.MaxAge)
```

The result is `jsonwt true -1`. The set cookie is scoped to `/` and expires no
later than the token. Deletion writes the same cookie with a negative `MaxAge`.
`FromCookie`, like the bearer helper, only decodes; validate before use. See
the [`SetCookie`, `FromCookie`, and `DeleteCookie`
reference](https://pkg.go.dev/github.com/mdhender/jsonwt#SetCookie) and the
[security boundaries](security.md).

## Carry a validated token through context.Context

**Goal:** validate once at an HTTP boundary and make the token available to
downstream functions.

**Prerequisites:** an encoded token, its expected factory, and
`net/http/httptest`.

Parse first, attach the validated token to the request context, and retrieve it
with the package helper:

```go
validated, err := factory.Parse(encodedToken)
if err != nil {
	panic(err)
}

request := httptest.NewRequest(http.MethodGet, "/profile", nil)
ctx := validated.NewContext(request.Context())
request = request.WithContext(ctx)

received, ok := jsonwt.FromContext(request.Context())
if !ok {
	panic("token missing from context")
}
fmt.Println(received == validated)
```

Context storage does not validate a token; the ordering above is the safety
property. The result is `true`. See the [`Token.NewContext` and `FromContext`
reference](https://pkg.go.dev/github.com/mdhender/jsonwt#FromContext) and the
[security boundaries](security.md).

## Rotate a local signing key and factory

**Goal:** start issuing tokens with a new local key and understand the effect
on existing tokens.

**Prerequisites:** the current local key ID and secret, plus a replacement key
ID and secret.

Create a new factory with both a new key ID and secret, then route all new
issuance and validation through it:

```go
oldFactory := newFactory("local-key-1", "old-local-secret")
oldToken, err := oldFactory.Token(10*time.Minute, nil)
if err != nil {
	panic(err)
}

newFactory := newFactory("local-key-2", "new-local-secret")
_, err = newFactory.Parse(oldToken.String())
fmt.Println(errors.Is(err, jsonwt.ErrUnauthorized))

newToken, err := newFactory.Token(10*time.Minute, nil)
if err != nil {
	panic(err)
}
_, err = newFactory.Parse(newToken.String())
fmt.Println(err == nil)
```

Both results are `true`: the new factory rejects old tokens and accepts newly
issued ones. The package does not keep a key ring or grace period. If a local
tool needs a transition window, retain both factories temporarily and select
the old one outside this package by trusted configuration—not by unverified
token data. See the [`NewFactory` reference](https://pkg.go.dev/github.com/mdhender/jsonwt#NewFactory)
and the [key-management limits](security.md).

## Diagnose malformed, invalid, and expired tokens

**Goal:** map package errors to stable categories without comparing error text.

**Prerequisites:** a configured factory and, to diagnose expiration, an encoded
token whose expiration time has elapsed.

Use `errors.Is` with the exported sentinel errors:

```go
_, err := factory.Parse("not-a-token")
fmt.Println(errors.Is(err, jsonwt.ErrBadToken))

_, err = factory.Token(0, nil)
fmt.Println(errors.Is(err, jsonwt.ErrInvalid))

_, err = factory.Parse(expiredToken())
fmt.Println(errors.Is(err, jsonwt.ErrInvalid))
```

All three results are `true`. `ErrBadToken` means the compact encoding or JSON
is malformed. `ErrInvalid` covers an invalid lifetime, including an expired
token; expiration is not a separate sentinel. `ErrUnauthorized` identifies an
algorithm, key ID, or signature mismatch. `ErrBadFactory` identifies missing
factory configuration, while `ErrMissingClaim` means a valid token has no
application claim. See the [sentinel error
reference](https://pkg.go.dev/github.com/mdhender/jsonwt#pkg-constants) and the
[security boundaries](security.md).
