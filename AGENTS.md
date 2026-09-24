# Repository Guide

## Overview

This repository is a small, dependency-free Go module that implements JSON Web Tokens and an example HTTP server.

- Module: `github.com/mdhender/jsonwt`
- Go version: 1.17
- Core package: repository root (`package jsonwt`)
- Signer implementations: `signers/`
- Example server: `cmd/server/`

## Development Workflow

Use the Go toolchain installed by `.agents/setup`.

Before completing a change, run:

```sh
gofmt -w <changed-go-files>
go test ./...
go vet ./...
go build ./...
```

The module currently has no third-party dependencies or required environment variables, databases, or services.

## Code Guidelines

- Preserve compatibility with Go 1.17 unless a task explicitly changes the supported version.
- Prefer the standard library; add a dependency only when it provides clear value that cannot be achieved simply in-tree.
- Keep token encoding, signing, validation, cookie, and request-extraction responsibilities in their existing files.
- Keep exported sentinel errors and error types in `errors.go`.
- Add concise Go documentation for exported identifiers.
- Use idiomatic Go formatting and naming; do not introduce one-use abstractions.
- Preserve public API behavior unless the requested change explicitly requires a breaking change.

## Testing

- Add focused tests for behavior changes and bug fixes.
- Prefer table-driven tests when several inputs exercise the same contract.
- Assert returned values and errors, not only that a call succeeds.
- Include malformed token inputs and relevant time boundaries when changing decoding or validation.
