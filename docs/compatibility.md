# Compatibility policy

This policy applies beginning with the `v1.0.0` release.

## Go API

Releases within v1 preserve source compatibility for exported identifiers and
their documented behavior. Minor releases may add exported API, and patch
releases may fix behavior that contradicts the documented contract, but a
change that requires existing callers to edit correct code requires a new
major version.

The v1 module path remains `github.com/mdhender/jsonwt`. Go modules do not use
a `/v1` suffix. A future incompatible v2 API would use the module path
`github.com/mdhender/jsonwt/v2`.

The minimum supported Go version remains Go 1.17 throughout v1. CI checks both
Go 1.17 and the current stable Go release.

## Token wire format

The [token format reference](token-format.md) is the v1 wire contract. v1
releases continue to accept valid tokens produced by earlier v1 releases and
do not silently change the encoded meanings, required fields, signature input,
or time boundaries documented there.

Changing the compact layout, header or payload representation, application
claim encoding, signature interpretation, or documented validation boundaries
in an incompatible way requires a major-version plan. New optional data may be
introduced within v1 only when older v1 readers can safely ignore it and
existing valid tokens keep their meaning.

Compatibility does not require retaining behavior that bypasses signature
verification or accepts malformed input contrary to the documented contract.
A security or correctness fix may reject such input and will be called out in
the changelog.

## Version source

Annotated Git tags such as `v1.0.0` are the sole version source. The package
does not expose a separately maintained version constant or function, so code
and release metadata cannot silently disagree. See the [release
checklist](releasing.md) for the tagging process.
