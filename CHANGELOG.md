# Changelog

This project records user-visible changes in this file and uses semantic
versioning for releases.

## 1.0.0 (unreleased)

### Initial contract

- Issue and verify signed, JWT-shaped tokens through `Factory.Token`,
  `Factory.Parse`, and `Factory.Validate`.
- Encode one optional application claim as JSON inside the package-specific
  token format.
- Sign and verify with the dependency-free HS256 signer.
- Enforce inclusive `iat` and `nbf` boundaries and an exclusive `exp`
  boundary, with injectable factory clocks for deterministic tests.
- Transport tokens through bearer headers, the package cookie, and
  `context.Context` helpers without treating extraction as verification.
- Return stable sentinel error categories for malformed, invalid,
  unauthorized, and missing-claim cases.

### Known limitations

- The token format is package-specific and is not an RFC 7519-compatible JWT
  format.
- The package is intended only for local tools, tests, demos, and trusted
  prototypes—not production authentication, authorization, or sessions.
- Tokens are signed but not encrypted. There is no key management, issuer or
  audience policy, revocation, replay protection, refresh-token support, JWKS,
  OIDC discovery, or asymmetric signing.
- The only built-in signer is HS256, and callers are responsible for choosing
  and protecting an appropriate shared secret.
- Application data is represented as one nested, base64url-encoded JSON claim
  rather than as arbitrary top-level JWT claims.

### Removed before v1

- Removed the hard-coded `Version` function. Git release tags are the sole
  source of package version truth.
