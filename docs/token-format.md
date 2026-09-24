# Token format reference

This page defines the jsonwt v1 wire format. It is a factual companion to the
[Go API reference](https://pkg.go.dev/github.com/mdhender/jsonwt); for usage
steps, see the [tutorial](tutorial.md) and [how-to guides](how-to.md).

jsonwt tokens are JWT-shaped but are not general-purpose JSON Web Tokens. They
use package-specific fields and encode application claims differently from RFC
7519. Do not assume that another JWT implementation can issue or consume them.
The payload and application claim are encoded, not encrypted. See [Security and
scope](security.md).

## Compact layout

A token contains exactly three non-empty sections separated by ASCII periods:

```text
base64url(header JSON).base64url(payload JSON).base64url(signature bytes)
```

Each section uses the unpadded raw URL-safe base64 alphabet defined by
`encoding/base64.RawURLEncoding`. The signature input is the exact ASCII byte
sequence of the encoded header, one period, and the encoded payload:

```text
base64url(header JSON).base64url(payload JSON)
```

`Decode` preserves the original encoded sections rather than re-encoding their
JSON. `Factory.Validate` therefore checks the signature over the bytes that
were transported. Unknown JSON object members are ignored while decoding but
remain covered by that preserved signature input. Calling `Factory.Sign`
regenerates both JSON objects from the known fields and drops unknown members.

## Header object

The first section decodes to a JSON object with these fields:

| Field | JSON type | Validation | Meaning |
| --- | --- | --- | --- |
| `ver` | integer | Not checked | jsonwt format version. `NewToken` sets integer `1`. |
| `alg` | string | Must exactly match | Identifier returned by `Signer.Algorithm`. The built-in signer uses `HS256`. |
| `typ` | string | Not checked | `NewToken` sets `JWT`. |
| `kid` | string | Must exactly match | `Factory.ID` of the signing factory. |
| `cty` | string | Not checked | Content-type metadata. The v1 API does not set or interpret it. |

`Factory.Token` starts with `NewToken`, so its output contains `ver` and `typ`.
`Factory.Sign` replaces `alg` and `kid` with its own values but preserves the
other header fields already in the Token. Validation requires exact `alg` and
`kid` matches before checking the signature. It does not independently enforce
`ver`, `typ`, or `cty`; all header bytes are nevertheless covered by the
signature.

## Payload object

The second section decodes to a JSON object with these fields:

| Field | JSON type | Presence | Meaning |
| --- | --- | --- | --- |
| `iss` | string | Optional | Issuer metadata. The v1 API does not expose, set, or validate it. |
| `sub` | string | Optional | Subject metadata. The v1 API does not expose, set, or validate it. |
| `aud` | array of strings | Optional | Audience metadata. The v1 API does not expose, set, or validate it. |
| `exp` | integer | Required for validity | Exclusive expiration boundary as Unix seconds. |
| `nbf` | integer | Optional | Inclusive not-before boundary as Unix seconds. Zero means no not-before restriction. |
| `iat` | integer | Required for validity | Inclusive issued-at boundary as Unix seconds. |
| `jti` | string | Optional | Token ID metadata. The v1 API does not expose, set, or validate it. |
| `claim` | string | Optional | Package-specific application claim described below. |

`NewToken` sets `iat` to the current UTC Unix second and `exp` to the Unix
second represented by current time plus the requested TTL. It sets no `nbf`.
Time values have one-second precision.

At a time `now`, a signed token is valid exactly when all these conditions hold:

```text
iat != 0
exp != 0
now >= iat
nbf == 0 or now >= nbf
now < exp
```

Thus `iat` and `nbf` are inclusive, while `exp` is exclusive. A token is valid
at its issue and not-before seconds and invalid starting at its expiration
second.

## Application claim

The `claim` field is not the RFC 7519 claim set. jsonwt uses the payload object
for its fixed fields and stores one arbitrary application value inside
`claim`.

For a non-nil value passed to `NewToken` or `Factory.Token`, jsonwt:

1. marshals the value as JSON;
2. raw-URL-base64 encodes those JSON bytes; and
3. stores the resulting base64 text as the payload object's `claim` string.

The payload object itself is then JSON-marshaled and base64url-encoded as the
compact token's second section. The application claim is consequently encoded
once inside an encoded payload; it is not encrypted. A nil claim omits the
field. `Token.Claim` reverses the inner base64 encoding and JSON-unmarshals the
result into the caller's destination.

## Signature

The third section is the raw-URL-base64 encoding of the bytes returned by
`Signer.Sign`. The built-in `signers.HS256` implementation computes
HMAC-SHA-256 over the signature input with its copied shared secret.

`Decode` only requires the signature section to be non-empty. Signature base64
syntax is checked by `Factory.Validate`, which compares decoded signature bytes
with a newly generated signature using constant-time comparison.

## Parsing and verification

The operations have distinct trust guarantees:

| Operation | Framing and JSON | Factory metadata | Signature | Times |
| --- | --- | --- | --- | --- |
| `Decode` | Checked | Not checked | Not checked | Not checked |
| `FromBearerToken`, `FromCookie`, `FromRequest` | Checked via `Decode` | Not checked | Not checked | Not checked |
| `Factory.Validate` | Assumes an already decoded `Token` | Checked | Checked | Checked |
| `Factory.Parse` | Checked via `Decode` | Checked | Checked | Checked |

`Factory.Parse` is the complete operation for an encoded token. A successful
parse returns a token whose claim can be consumed. Extraction helpers return
unverified tokens and must be followed by `Factory.Validate`.

## Interoperability and compatibility

Deliberate differences from general-purpose JWT and RFC 7519 include:

- the jsonwt-specific `ver` header;
- the nested, base64-encoded `claim` payload field rather than arbitrary claims
  directly in the payload object;
- integer-only `iat`, `nbf`, and `exp` values rather than the broader RFC 7519
  NumericDate representation;
- an array-of-strings-only `aud` field rather than accepting either one string
  or an array;
- a fixed opaque `Token` API rather than a general claim-set API;
- no algorithm negotiation, asymmetric signatures, JWKS, or OIDC discovery;
  and
- no validation of `iss`, `sub`, `aud`, or `jti` metadata.

The module path is `github.com/mdhender/jsonwt`, with no `/v1` suffix. The v1
API supports Go 1.17 and later. Exported API behavior and this documented wire
format remain compatible throughout v1; an incompatible change requires a new
major version.
