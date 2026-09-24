package jsonwt_test

import (
	"fmt"
	"strings"
	"time"

	"github.com/mdhender/jsonwt"
	"github.com/mdhender/jsonwt/signers"
)

func Example() {
	type applicationClaim struct {
		User  string   `json:"user"`
		Roles []string `json:"roles"`
	}

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

	// Output:
	// token sections: 3
	// user: ada
	// roles: [reader writer]
}
