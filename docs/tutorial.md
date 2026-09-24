# Issue and consume your first token

This tutorial builds a complete program that issues a signed token containing
an application claim, serializes it for transport, parses and validates it,
and reads the claim back.

Use this package only for local tools, demos, tests, and trusted internal
prototypes. It is not a production authentication system. See
[Security and scope](security.md) for the boundaries behind that warning.

## Before you begin

You need Go 1.17 or later. Create a directory for the tutorial and initialize a
module:

```sh
mkdir jsonwt-tutorial
cd jsonwt-tutorial
go mod init example.com/jsonwt-tutorial
go get github.com/mdhender/jsonwt@latest
```

## Build the program

Create `main.go` with the following contents:

```go
package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/mdhender/jsonwt"
	"github.com/mdhender/jsonwt/signers"
)

type applicationClaim struct {
	User  string   `json:"user"`
	Roles []string `json:"roles"`
}

func main() {
	signer, err := signers.NewHS256([]byte("local-demo-secret-change-me"))
	if err != nil {
		panic(err)
	}
	factory := jsonwt.NewFactory("tutorial-key", signer)

	claim := applicationClaim{
		User:  "ada",
		Roles: []string{"reader", "writer"},
	}
	token, err := factory.Token(15*time.Minute, claim)
	if err != nil {
		panic(err)
	}
	encoded := token.String()
	fmt.Println("token sections:", len(strings.Split(encoded, ".")))

	parsed, err := factory.Parse(encoded)
	if err != nil {
		panic(err)
	}
	var decoded applicationClaim
	if err := parsed.Claim(&decoded); err != nil {
		panic(err)
	}

	fmt.Println("user:", decoded.User)
	fmt.Println("roles:", decoded.Roles)
}
```

This is the same program compiled and run by the repository's `Example` test.

## Understand each step

### 1. Create the signer and factory

`signers.NewHS256` creates a signer from a shared secret. It rejects an empty
secret. The tutorial secret is deliberately visible and is suitable only for
this local example; do not embed real secrets in source code.

`jsonwt.NewFactory` pairs that signer with the key ID `tutorial-key`. The key ID
identifies the local signing configuration—it does not fetch or manage keys.
Keep both the key ID and secret consistent wherever this program later parses
the token. A different ID or secret causes `Factory.Parse` to return
`jsonwt.ErrUnauthorized`.

### 2. Define an application claim

`applicationClaim` is ordinary JSON-marshalable Go data. Export claim fields so
`encoding/json` can encode them. JSON tags keep the serialized names explicit.

### 3. Issue and serialize the token

`factory.Token` creates and signs the token in one call. Its first argument is
a positive time-to-live; use at least one second because token timestamps have
one-second precision. The example uses 15 minutes.

`token.String()` returns the compact `header.payload.signature` form. The
program prints only its section count because timestamps and signatures vary
between runs. Printing a complete token can expose its claim, so do that only
when a disposable local example requires it.

### 4. Parse and validate the token

`factory.Parse(encoded)` is the normal consumption path. It decodes the token
and verifies its algorithm, key ID, signature, and lifetime. Do not replace it
with `jsonwt.Decode`: `Decode` deliberately returns unverified data.

Parsing must use a factory configured with the same key ID and secret that
issued the token. Malformed, tampered, expired, or differently signed tokens
return an error and no token.

### 5. Extract the claim

After `Parse` succeeds, pass a pointer to the expected claim shape to
`parsed.Claim`. Passing a non-pointer cannot be populated. A token created with
a nil claim returns `jsonwt.ErrMissingClaim` here.

## Run it

```sh
go run .
```

Expected output:

```text
token sections: 3
user: ada
roles: [reader writer]
```

You have now completed the supported happy path: create, sign, serialize,
parse, validate, and extract. For exact API signatures and error contracts,
use the [Go API reference](https://pkg.go.dev/github.com/mdhender/jsonwt).
