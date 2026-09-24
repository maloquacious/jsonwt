/*******************************************************************************
jsonwt - JSON Web Tokens
Copyright (c) 2022 Michael D Henderson

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
******************************************************************************/

package jsonwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

type testSigner string

func (s testSigner) Algorithm() string { return "HS256" }

func (s testSigner) Sign(msg []byte) ([]byte, error) {
	h := hmac.New(sha256.New, []byte(s))
	_, _ = h.Write(msg)
	return h.Sum(nil), nil
}

var errTestSigner = errors.New("test signer error")

type failingSigner struct{}

func (failingSigner) Algorithm() string { return "HS256" }

func (failingSigner) Sign([]byte) ([]byte, error) { return nil, errTestSigner }

func TestFactoryParse(t *testing.T) {
	f := NewFactory("key-1", testSigner("secret"))
	token, err := f.Token(time.Hour, struct {
		Role string `json:"role"`
	}{Role: "reader"})
	if err != nil {
		t.Fatalf("Token() error = %v", err)
	}

	parsed, err := f.Parse(token.String())
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if !parsed.IsValid() {
		t.Fatal("Parse() returned an invalid token")
	}
	var claim struct {
		Role string `json:"role"`
	}
	if err = parsed.Claim(&claim); err != nil {
		t.Fatalf("Claim() error = %v", err)
	}
	if claim.Role != "reader" {
		t.Errorf("claim role = %q, want %q", claim.Role, "reader")
	}
}

func TestFactoryParseRejectsInvalidTokens(t *testing.T) {
	f := NewFactory("key-1", testSigner("secret"))
	token, err := f.Token(time.Hour, map[string]string{"role": "reader"})
	if err != nil {
		t.Fatalf("Token() error = %v", err)
	}
	encoded := token.String()

	expired := &Token{}
	expired.p.IssuedAt = 1
	expired.p.ExpirationTime = 2
	if err = f.Sign(expired); err != nil {
		t.Fatalf("Sign(expired) error = %v", err)
	}

	alteredSignature := strings.Split(encoded, ".")
	rawSignature, err := base64.RawURLEncoding.DecodeString(alteredSignature[2])
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	rawSignature[0] ^= 0xff
	alteredSignature[2] = base64.RawURLEncoding.EncodeToString(rawSignature)

	tests := []struct {
		name    string
		factory *Factory
		data    string
		want    error
	}{
		{name: "wrong key", factory: NewFactory("key-1", testSigner("other-secret")), data: encoded, want: ErrUnauthorized},
		{name: "altered header", factory: f, data: replaceTokenJSON(t, encoded, 0, "cty", "tampered"), want: ErrUnauthorized},
		{name: "altered payload", factory: f, data: replaceTokenJSON(t, encoded, 1, "sub", "altered"), want: ErrUnauthorized},
		{name: "altered signature", factory: f, data: strings.Join(alteredSignature, "."), want: ErrUnauthorized},
		{name: "wrong algorithm", factory: f, data: replaceTokenJSON(t, encoded, 0, "alg", "none"), want: ErrUnauthorized},
		{name: "wrong key ID", factory: f, data: replaceTokenJSON(t, encoded, 0, "kid", "key-2"), want: ErrUnauthorized},
		{name: "expired", factory: f, data: expired.String(), want: ErrInvalid},
		{name: "empty factory ID", factory: NewFactory("", testSigner("secret")), data: encoded, want: ErrBadFactory},
		{name: "nil signer", factory: NewFactory("key-1", nil), data: encoded, want: ErrBadFactory},
		{name: "nil factory", factory: nil, data: encoded, want: ErrBadFactory},
		{name: "empty input", factory: f, data: "", want: ErrBadToken},
		{name: "missing section", factory: f, data: "header.payload", want: ErrBadToken},
		{name: "malformed header encoding", factory: f, data: "%.e30.signature", want: ErrBadToken},
		{name: "malformed header JSON", factory: f, data: "e30x.e30.signature", want: ErrBadToken},
		{name: "malformed payload encoding", factory: f, data: "e30.%.signature", want: ErrBadToken},
		{name: "malformed payload JSON", factory: f, data: "e30.e30x.signature", want: ErrBadToken},
		{name: "malformed signature", factory: f, data: replaceTokenSection(encoded, 2, "%"), want: ErrBadToken},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.factory.Parse(tt.data)
			if got != nil {
				t.Errorf("Parse() token = %v, want nil", got)
			}
			if !errors.Is(err, tt.want) {
				t.Errorf("Parse() error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestFactoryTokenWithoutClaim(t *testing.T) {
	f := NewFactory("key-1", testSigner("secret"))
	token, err := f.Token(time.Hour, nil)
	if err != nil {
		t.Fatalf("Token() error = %v", err)
	}
	parsed, err := f.Parse(token.String())
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if parsed.HasClaim() {
		t.Error("HasClaim() = true, want false")
	}
	var claim interface{}
	if err = parsed.Claim(&claim); !errors.Is(err, ErrMissingClaim) {
		t.Errorf("Claim() error = %v, want %v", err, ErrMissingClaim)
	}
}

func TestFactoryPropagatesSignerErrors(t *testing.T) {
	failing := NewFactory("key-1", failingSigner{})
	tests := []struct {
		name string
		run  func() error
	}{
		{name: "Sign", run: func() error {
			token, err := NewToken(time.Hour, nil)
			if err != nil {
				t.Fatalf("NewToken() error = %v", err)
			}
			return failing.Sign(token)
		}},
		{name: "Token", run: func() error {
			_, err := failing.Token(time.Hour, nil)
			return err
		}},
		{name: "Validate", run: func() error {
			token := newSignedTestToken(t)
			return failing.Validate(token)
		}},
		{name: "Parse", run: func() error {
			token := newSignedTestToken(t)
			_, err := failing.Parse(token.String())
			return err
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.run(); !errors.Is(err, errTestSigner) {
				t.Errorf("error = %v, want %v", err, errTestSigner)
			}
		})
	}
}

func TestFactoryNilReceiverID(t *testing.T) {
	if got := NewFactory("key-1", testSigner("secret")).ID(); got != "key-1" {
		t.Errorf("ID() = %q, want %q", got, "key-1")
	}
	if got := (*Factory)(nil).ID(); got != "" {
		t.Errorf("ID() = %q, want empty string", got)
	}
}

func TestFactoryOperationsRejectBadConfiguration(t *testing.T) {
	tests := []struct {
		name    string
		factory *Factory
	}{
		{name: "nil factory", factory: nil},
		{name: "empty key ID", factory: NewFactory("", testSigner("secret"))},
		{name: "nil signer", factory: NewFactory("key-1", nil)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.factory.Sign(newSignedTestToken(t)); !errors.Is(err, ErrBadFactory) {
				t.Errorf("Sign() error = %v, want %v", err, ErrBadFactory)
			}
			if token, err := tt.factory.Token(time.Hour, nil); token != nil || !errors.Is(err, ErrBadFactory) {
				t.Errorf("Token() = (%v, %v), want (nil, %v)", token, err, ErrBadFactory)
			}
			if err := tt.factory.Validate(newSignedTestToken(t)); !errors.Is(err, ErrBadFactory) {
				t.Errorf("Validate() error = %v, want %v", err, ErrBadFactory)
			}
		})
	}
}

func TestFactoryValidateContract(t *testing.T) {
	f := NewFactory("key-1", testSigner("secret"))
	token, err := f.Token(time.Hour, nil)
	if err != nil {
		t.Fatalf("Token() error = %v", err)
	}
	decoded, err := Decode(token.String())
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if err = f.Validate(decoded); err != nil {
		t.Errorf("Validate(valid token) error = %v", err)
	}

	expired := &Token{}
	expired.p.IssuedAt = 1
	expired.p.ExpirationTime = 2
	if err = f.Sign(expired); err != nil {
		t.Fatalf("Sign(expired) error = %v", err)
	}
	decoded, err = Decode(expired.String())
	if err != nil {
		t.Fatalf("Decode(expired) error = %v", err)
	}
	if err = f.Validate(decoded); !errors.Is(err, ErrInvalid) {
		t.Errorf("Validate(expired token) error = %v, want %v", err, ErrInvalid)
	}

	if err := f.Validate(nil); !errors.Is(err, ErrInvalid) {
		t.Errorf("Validate(nil) error = %v, want %v", err, ErrInvalid)
	}
	if err := f.Sign(nil); !errors.Is(err, ErrInvalid) {
		t.Errorf("Sign(nil) error = %v, want %v", err, ErrInvalid)
	}
}

func replaceTokenJSON(t *testing.T, token string, section int, key string, value interface{}) string {
	t.Helper()
	sections := strings.Split(token, ".")
	raw, err := base64.RawURLEncoding.DecodeString(sections[section])
	if err != nil {
		t.Fatalf("decode token section: %v", err)
	}
	var data map[string]interface{}
	if err = json.Unmarshal(raw, &data); err != nil {
		t.Fatalf("unmarshal token section: %v", err)
	}
	data[key] = value
	raw, err = json.Marshal(data)
	if err != nil {
		t.Fatalf("marshal token section: %v", err)
	}
	sections[section] = base64.RawURLEncoding.EncodeToString(raw)
	return strings.Join(sections, ".")
}

func replaceTokenSection(token string, section int, value string) string {
	sections := strings.Split(token, ".")
	sections[section] = value
	return strings.Join(sections, ".")
}

func newSignedTestToken(t *testing.T) *Token {
	t.Helper()
	token, err := NewFactory("key-1", testSigner("secret")).Token(time.Hour, nil)
	if err != nil {
		t.Fatalf("Token() error = %v", err)
	}
	return token
}
