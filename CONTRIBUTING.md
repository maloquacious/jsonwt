# Contributing

jsonwt supports Go 1.17 and later and has no third-party dependencies.

Before submitting a change, run these checks from the repository root:

```sh
test -z "$(gofmt -l $(find . -type f -name '*.go'))"
go test ./...
go vet ./...
go build ./...
```

Run `gofmt -w` on changed Go files when the formatting check reports a path.
CI runs the same commands with Go 1.17 and the current stable Go release on
pull requests and on pushes to `main`.

Behavior changes and bug fixes should include focused tests. Preserve the
public API and token wire-format commitments described in the
[compatibility policy](docs/compatibility.md).
