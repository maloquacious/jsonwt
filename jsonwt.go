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

// Package jsonwt defines a JSON Web Token type that's stored in Cookies and Contexts.
package jsonwt

import (
	"encoding/json"
	"time"
)

// NewToken will return an unsigned Token (the caller must use a Factory to sign the token).
// `ttl` is the time-to-live for the token.
// `scope` is the optional private payload for use by the application.
// If provided, scope will be marshalled to JSON, then base64 encoded.
func NewToken(ttl time.Duration, scope interface{}) (*Token, error) {
	var t Token
	t.h.Version = 1
	t.h.TokenType = "JWT"
	t.p.IssuedAt = time.Now().Unix()
	t.p.ExpirationTime = time.Now().Add(ttl).Unix()
	if scope != nil { // scope is optional.
		b, err := json.Marshal(scope)
		if err != nil {
			return nil, err
		}
		t.p.Scope = encode(b)
	}
	return &t, nil
}

// Token implements my version of the JSON Web Token.
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
		// Scope is private data for use by the application.
		Scope string `json:"scope,omitempty"`
		b64   string // payload marshalled to JSON and then base-64 encoded
	}
	s        string // signature base-64 encoded
	isSigned bool   // true only if the signature has been verified
}
