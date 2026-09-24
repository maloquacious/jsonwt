# Security and scope

`jsonwt` deliberately optimizes for a small API and predictable behavior in
non-production environments. It is useful when a local program, test, example,
or disposable demo needs to pass a signed JSON value without introducing a
complete authentication system. That narrow scope is a product choice, not a
claim that a small token implementation is secure enough for production.

## Decide whether it fits

The deciding question is whether accepting a token grants trust across a
boundary where another person, tenant, service, or network participant could
benefit from forging, stealing, replaying, or observing it.

| Use this when | Do not use this when |
| --- | --- |
| Running local development tools and experiments. | Authenticating or authorizing internet-facing requests. |
| Writing tests that need a compact signed value. | Protecting browser or application sessions. |
| Publishing examples with disposable data and secrets. | Separating tenants, users, services, or other security principals. |
| Building a disposable demo in a controlled environment. | Accepting tokens from untrusted or independently managed issuers. |
| Prototyping among trusted participants before security requirements apply. | Meeting compliance, audit, privacy, or adversarial-input requirements. |

“Trusted” does not mean merely “inside our network.” It means that compromise,
misconfiguration, disclosure, or malicious input cannot create a meaningful
security loss. If that is not clearly true, use a maintained,
security-focused JWT or OIDC solution instead.

## What a signature means

The built-in signer computes an HS256 HMAC with a shared secret. When that
secret is strong, protected, and known only to trusted participants, successful
validation shows that the signed bytes have not changed since a holder of the
secret produced them.

That property is deliberately limited:

- A signature does not encrypt anything. The header, payload, and application
  claim are encoded and can be read by anyone who obtains the token. Do not put
  passwords, private keys, personal data, or other secrets in a token.
- A shared secret does not prove which holder created a token. Every party that
  can validate an HS256 token with the secret can also create one.
- A signature does not provide key generation, secure storage, distribution,
  rotation, or compromise recovery. The package accepts any non-empty secret;
  acceptance is not evidence that a secret is strong.
- A valid signature does not prevent a captured token from being replayed. The
  package has no revocation list, one-time-use enforcement, refresh-token
  system, or server-side session state.
- A signature does not make application authorization decisions. A validated
  claim is data, not permission to perform an action.

Default, short, checked-in, or embedded secrets—such as the literal `secret`
in the example server—are public credentials. They are suitable only for the
disposable environment in which they are shown. Copying that server or its
secret into deployed software does not create an authentication service.

## Why the package stays small

The narrow design makes the supported path easy to read and teach: one local
factory issues a token, the same trusted configuration validates it, and an
application claim round-trips through ordinary JSON. There is no algorithm
negotiation, remote key lookup, issuer discovery, or framework lifecycle to
configure. The package is dependency-free and its custom wire format is small
enough to document completely.

Production identity systems need the complexity that `jsonwt` omits. In
particular, this package does not provide:

- asymmetric signing or separation of signing and verification authority;
- trusted algorithm allowlists beyond one factory's configured signer;
- JWKS key distribution or OIDC issuer discovery;
- issuer, subject, or audience policy;
- refresh-token rotation, revocation, or replay detection;
- framework middleware or secure browser-session policy; or
- claims encryption.

Adding isolated versions of those features would not by itself establish a
secure deployment model. They interact with key custody, issuer trust,
protocol validation, storage, transport, monitoring, and incident response.
Rather than present a partial system as production-ready, `jsonwt` keeps those
concerns explicitly out of scope. See [Differences from RFC
7519](rfc-7519.md) for a standards comparison and the hypothetical work a
compliance project would require.

## Correctness still matters

Non-production scope is not permission for incorrect behavior. Malformed input
must return an error rather than panic. Validation must bind the configured
algorithm and key ID, verify the signature over the transported bytes, and
enforce documented issue, not-before, and expiration boundaries. HTTP helpers
must not silently turn decoding into trust. Tests must cover malformed input,
tampering, and exact time boundaries without weakening those contracts.

These properties make the package predictable for its intended uses. They do
not add confidentiality, establish an issuer's identity, or make hostile input
safe enough for a production authentication boundary. Use [`Factory.Parse` or
`Factory.Validate`](https://pkg.go.dev/github.com/mdhender/jsonwt#Factory) even
in a local environment; `Decode` and the HTTP extraction helpers return
unverified data. The [token format reference](token-format.md) defines the
exact validation contract.

## Cross the boundary deliberately

Move to a maintained, security-focused JWT or OIDC solution before a prototype
protects real accounts or data, accepts traffic across an untrusted network,
adds independently managed issuers, separates tenants, or becomes subject to
security or compliance requirements. Do not wait for deployment to discover
that the token format, key model, and session lifecycle must all change.

Migration means replacing the trust model, not merely decoding the existing
custom tokens with another library. Define trusted issuers and audiences,
choose an algorithm and key-management policy, design expiration, refresh,
revocation, and replay behavior, and test authorization independently of token
validation. This project does not endorse one dependency because maintenance
and security posture change; evaluate current, actively maintained options
against those requirements.

For procedures within the supported scope, use the [tutorial](tutorial.md) and
[how-to guides](how-to.md). For exact behavior, use the [Go API
reference](https://pkg.go.dev/github.com/mdhender/jsonwt) and [token format
reference](token-format.md).
