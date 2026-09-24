package jsonwt_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/mdhender/jsonwt"
	"github.com/mdhender/jsonwt/signers"
)

type sessionClaim struct {
	User string   `json:"user"`
	Tags []string `json:"tags"`
}

type fixedClock struct {
	now time.Time
}

func (c *fixedClock) Now() time.Time { return c.now }

func newFactory(keyID, secret string) *jsonwt.Factory {
	signer, err := signers.NewHS256([]byte(secret))
	if err != nil {
		panic(err)
	}
	return jsonwt.NewFactory(keyID, signer)
}

func Example_testClock() {
	signer, err := signers.NewHS256([]byte("test-secret"))
	if err != nil {
		panic(err)
	}
	clock := &fixedClock{now: time.Unix(1_700_000_000, 0)}
	factory := jsonwt.NewFactoryWithClock("test-key", signer, clock)

	token, err := factory.Token(time.Minute, nil)
	if err != nil {
		panic(err)
	}

	clock.now = clock.now.Add(time.Minute)
	fmt.Println(token.IsValid())

	// Output:
	// false
}

func Example_customClaims() {
	factory := newFactory("local-key", "local-demo-secret-change-me")
	issued, err := factory.Token(10*time.Minute, sessionClaim{
		User: "ada",
		Tags: []string{"reader", "tester"},
	})
	if err != nil {
		panic(err)
	}

	parsed, err := factory.Parse(issued.String())
	if err != nil {
		panic(err)
	}
	var claim sessionClaim
	if err := parsed.Claim(&claim); err != nil {
		panic(err)
	}
	fmt.Println(claim.User, claim.Tags)

	// Output:
	// ada [reader tester]
}

func Example_bearerToken() {
	factory := newFactory("local-key", "local-demo-secret-change-me")
	issued, err := factory.Token(10*time.Minute, sessionClaim{User: "ada"})
	if err != nil {
		panic(err)
	}

	request := httptest.NewRequest(http.MethodGet, "/profile", nil)
	request.Header.Set("Authorization", "Bearer "+issued.String())

	received := jsonwt.FromBearerToken(request)
	if received == nil {
		panic("missing bearer token")
	}
	if err := factory.Validate(received); err != nil {
		panic(err)
	}
	fmt.Println(received.IsValid())

	// Output:
	// true
}

func Example_cookies() {
	factory := newFactory("local-key", "local-demo-secret-change-me")
	issued, err := factory.Token(10*time.Minute, sessionClaim{User: "ada"})
	if err != nil {
		panic(err)
	}

	response := httptest.NewRecorder()
	issued.SetCookie(response)
	cookie := response.Result().Cookies()[0]

	request := httptest.NewRequest(http.MethodGet, "/profile", nil)
	request.AddCookie(cookie)
	received := jsonwt.FromCookie(request)
	if received == nil {
		panic("missing token cookie")
	}
	if err := factory.Validate(received); err != nil {
		panic(err)
	}

	response = httptest.NewRecorder()
	jsonwt.DeleteCookie(response)
	deleted := response.Result().Cookies()[0]
	fmt.Println(cookie.Name, cookie.HttpOnly, deleted.MaxAge)

	// Output:
	// jsonwt true -1
}

func Example_context() {
	factory := newFactory("local-key", "local-demo-secret-change-me")
	issued, err := factory.Token(10*time.Minute, sessionClaim{User: "ada"})
	if err != nil {
		panic(err)
	}
	validated, err := factory.Parse(issued.String())
	if err != nil {
		panic(err)
	}

	request := httptest.NewRequest(http.MethodGet, "/profile", nil)
	ctx := validated.NewContext(request.Context())
	request = request.WithContext(ctx)

	received, ok := jsonwt.FromContext(request.Context())
	if !ok {
		panic("token missing from context")
	}
	fmt.Println(received == validated)

	// Output:
	// true
}

func Example_keyRotation() {
	oldFactory := newFactory("local-key-1", "old-local-secret")
	oldToken, err := oldFactory.Token(10*time.Minute, nil)
	if err != nil {
		panic(err)
	}

	newFactory := newFactory("local-key-2", "new-local-secret")
	_, err = newFactory.Parse(oldToken.String())
	fmt.Println(errors.Is(err, jsonwt.ErrUnauthorized))

	newToken, err := newFactory.Token(10*time.Minute, nil)
	if err != nil {
		panic(err)
	}
	_, err = newFactory.Parse(newToken.String())
	fmt.Println(err == nil)

	// Output:
	// true
	// true
}

func Example_errors() {
	factory := newFactory("local-key", "local-demo-secret-change-me")

	_, err := factory.Parse("not-a-token")
	fmt.Println(errors.Is(err, jsonwt.ErrBadToken))

	_, err = factory.Token(0, nil)
	fmt.Println(errors.Is(err, jsonwt.ErrInvalid))

	_, err = factory.Parse(expiredToken())
	fmt.Println(errors.Is(err, jsonwt.ErrInvalid))

	// Output:
	// true
	// true
	// true
}

func expiredToken() string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"ver":1,"alg":"HS256","typ":"JWT","kid":"local-key"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"exp":2,"iat":1}`))
	message := header + "." + payload
	mac := hmac.New(sha256.New, []byte("local-demo-secret-change-me"))
	_, _ = mac.Write([]byte(message))
	return message + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
