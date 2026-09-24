# jsonwt

`jsonwt` is a small, dependency-free Go package for issuing and consuming
signed, JWT-shaped tokens in local tools, demos, tests, and trusted internal
prototypes. It intentionally provides a narrow API and token format rather
than implementing the JWT standard.

> **Warning:** Do not use `jsonwt` for production authentication,
> authorization, sessions, or across an untrusted network boundary. Tokens are
> signed but not encrypted, and the package does not provide key management,
> revocation, replay protection, or standards compatibility. Read
> [Security and scope](docs/security.md) before choosing it.

## Install

In a Go module, run:

```sh
go get github.com/mdhender/jsonwt@latest
```

The module supports Go 1.17 and later.

## Start here

Follow the [tutorial and concise user manual](docs/tutorial.md) to create an
HS256 signer, issue a token with an application claim, parse and validate the
token, and extract the claim.

## Documentation

- [Tutorial and user manual](docs/tutorial.md)
- [How-to guides](docs/how-to.md)
- [API reference](https://pkg.go.dev/github.com/mdhender/jsonwt)
- [Token format reference](docs/token-format.md)
- [RFC 7519 differences and hypothetical compliance steps](docs/rfc-7519.md)
- [Security and design explanation](docs/security.md)

## License

`jsonwt` is available under the [MIT License](LICENSE).
