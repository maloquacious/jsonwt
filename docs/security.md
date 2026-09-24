# Security and scope

`jsonwt` deliberately optimizes for a small API and predictable behavior in
non-production environments. Use it for local development, examples, tests,
disposable demos, and trusted internal prototypes that do not cross a trust
boundary.

Do not use it for internet-facing authentication, authorization, session
security, multi-tenant isolation, compliance controls, or processing tokens
from untrusted issuers. Choose a maintained, security-focused JWT or OIDC
implementation before crossing one of those boundaries.

An HS256 signature can detect changes when every participant protects the same
secret. It does not encrypt the header, payload, or application claim. It also
does not establish identity, distribute or rotate keys, revoke tokens, prevent
replay, or make an embedded secret safe.

The format is JWT-shaped but intentionally custom and is not promised to
interoperate with general-purpose JWT libraries. The package still rejects
malformed input, verifies signatures, and enforces token times; those
correctness properties do not turn it into a production security system.

Return to the [tutorial and user manual](tutorial.md).
