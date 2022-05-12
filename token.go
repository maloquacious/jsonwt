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
	"encoding/json"
	"net/http"
	"time"
)

// IsValid returns true only if the Token is signed, active, and not expired.
func (t *Token) IsValid() bool {
	now := time.Now().UTC()
	if t == nil {
		//log.Printf("jwt is nil\n")
		return false
	} else if !t.isSigned {
		//log.Printf("alg %q typ %q signed %v borked\n", j.h.Algorithm, j.h.TokenType, j.isSigned)
		return false
	} else if t.p.IssuedAt == 0 {
		//log.Printf("alg %q typ %q signed %v no issue timestamp\n", j.h.Algorithm, j.h.TokenType, j.isSigned)
		return false
	} else if t.p.ExpirationTime == 0 {
		//log.Printf("alg %q typ %q signed %v no expiration timestamp\n", j.h.Algorithm, j.h.TokenType, j.isSigned)
		return false
	} else if !now.After(time.Unix(t.p.IssuedAt, 0)) {
		//log.Printf("alg %q typ %q signed %v !now.After(issuedAt) %s %s\n", j.h.Algorithm, j.h.TokenType, j.isSigned, now.Format("2006-01-02T15:04:05.99999999Z"), time.Unix(j.p.IssuedAt, 0).Format("2006-01-02T15:04:05.99999999Z"))
		return false
	} else if !time.Unix(t.p.ExpirationTime, 0).After(now) {
		//log.Printf("alg %q typ %q signed %v !expiresAt.After(now)\n", j.h.Algorithm, j.h.TokenType, j.isSigned)
		return false
	} else if t.p.NotBefore != 0 && !now.Before(time.Unix(t.p.NotBefore, 0)) {
		//log.Printf("alg %q typ %q signed %v !now.Before(notBefore)\n", j.h.Algorithm, j.h.TokenType, j.isSigned)
		return false
	}
	return true
}

// DeleteCookie removes the cookie associated with the Token.
func (t *Token) DeleteCookie(w http.ResponseWriter) {
	DeleteCookie(w)
}

// SetCookie associates a cookie with the Token and sends it to the client.
func (t *Token) SetCookie(w http.ResponseWriter) {
	SetCookie(w, t)
}

// String implements the Stringer interface.
// Please don't call this before signing the token.
func (t *Token) String() string {
	return t.h.b64 + "." + t.p.b64 + "." + t.s
}

// Scope retrieves the private payload from the Token and marshals it into the given variable.
// It returns errors if the Token is not valid, has no private payload, or there's an error unmarshalling the data.
func (t *Token) Scope(v interface{}) error {
	if t == nil {
		return ErrBadToken
	} else if !t.IsValid() {
		return ErrInvalid
	} else if t.p.Scope == "" {
		return ErrMissingScope
	}
	b, err := decode(t.p.Scope)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}
