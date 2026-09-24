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

// Package jsonwt issues and verifies small, signed tokens for local tools,
// tests, demos, and trusted prototypes.
//
// Tokens use the familiar header.payload.signature shape, but their fields and
// claim representation are package-specific. This package is not a general
// RFC 7519 JWT implementation and its tokens are not promised to interoperate
// with JWT libraries. Token contents are encoded, not encrypted.
//
// The normal lifecycle is to create a Factory from a Signer, issue a signed
// Token with Factory.Token, transport Token.String, and consume it with
// Factory.Parse. Decode and the HTTP extraction helpers do not verify tokens.
//
// The v1 API supports Go 1.17 and later. Exported API behavior and the
// documented token wire format are compatibility commitments throughout v1;
// incompatible changes require a new major version.
package jsonwt

import (
	"encoding/json"
	"time"
)

// NewToken returns an unsigned Token issued at the current UTC time. The caller
// must use Factory.Sign before transporting or using it.
//
// ttl must be positive. NewToken records iat and exp as whole Unix seconds and
// returns ErrInvalid when ttl is zero or negative. A positive ttl shorter than
// one second can truncate to the same iat and exp and therefore produce an
// immediately invalid token; callers should use at least one second.
//
// If claim is non-nil, NewToken marshals it as JSON and stores its unpadded
// raw-URL-base64 representation in the package-specific claim field. JSON
// marshal errors are returned unchanged. A nil claim omits that field.
func NewToken(ttl time.Duration, claim interface{}) (*Token, error) {
	return newToken(ttl, claim, time.Now().UTC())
}

func newToken(ttl time.Duration, claim interface{}, now time.Time) (*Token, error) {
	if ttl <= 0 {
		return nil, ErrInvalid
	}

	var t Token
	t.h.Version = 1
	t.h.TokenType = "JWT"
	t.p.IssuedAt = now.Unix()
	t.p.ExpirationTime = now.Add(ttl).Unix()
	if claim != nil { // claim is optional.
		b, err := json.Marshal(claim)
		if err != nil {
			return nil, err
		}
		t.p.Claim = encode(b)
	}
	return &t, nil
}

// Token is a package-specific signed token. Its fields are intentionally
// opaque; use a Factory to create, sign, parse, and validate tokens, and use the
// Token methods to inspect their encoded sections and application claim.
//
// A Token returned by NewToken is unsigned. A Token returned by Decode or an
// HTTP extraction helper is unverified. Factory.Token returns a signed token,
// and Factory.Parse returns a decoded token only after successful validation.
type Token struct {
	h struct {
		Version     int    `json:"ver,omitempty"`
		Algorithm   string `json:"alg"` // message authentication code algorithm
		TokenType   string `json:"typ"` // should always be JWT
		KeyID       string `json:"kid"` // identifier used to sign
		ContentType string `json:"cty,omitempty"`
		b64         string // header marshalled to JSON and then base-64 encoded
	}
	p struct {
		// The principal that issued the Token.
		Issuer string `json:"iss,omitempty"`
		// The subject of the Token.
		Subject string `json:"sub,omitempty"`
		// The recipients that the Token is intended for.
		// Each principal intended to process the Token must identify itself with a value in the audience claim.
		// If the principal processing the claim does not identify itself with a value in the aud claim when this claim is present,
		// then the Token must be rejected.
		Audience []string `json:"aud,omitempty"`
		// The expiration time on and after which the Token must not be accepted for processing.
		// The value must be a NumericDate:[9] either an integer or decimal, representing seconds past 1970-01-01 00:00:00Z.
		ExpirationTime int64 `json:"exp,omitempty"`
		// The time on which the Token will start to be accepted for processing.
		// The value must be a NumericDate.
		NotBefore int64 `json:"nbf,omitempty"`
		// The time at which the Token was issued.
		// The value must be a NumericDate.
		IssuedAt int64 `json:"iat,omitempty"`
		// Case sensitive unique identifier of the token even among different issuers.
		JWTID string `json:"jti,omitempty"`
		// Claim is private data for use by the application.
		Claim string `json:"claim,omitempty"`
		b64   string // payload marshalled to JSON and then base-64 encoded
	}
	s        string // signature base-64 encoded
	isSigned bool   // true only if the signature has been verified
	clock    Clock  // clock associated by successful Factory operations
}
