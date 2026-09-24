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
	"net/http"
	"time"
)

// IsValid returns true only if the Token is signed, issued, active, and not
// expired. IssuedAt and NotBefore are inclusive boundaries; ExpirationTime is
// exclusive.
func (t *Token) IsValid() bool {
	return t.isValidAt(time.Now().UTC())
}

func (t *Token) isValidAt(now time.Time) bool {
	if t == nil {
		return false
	} else if !t.isSigned {
		return false
	} else if t.p.IssuedAt == 0 {
		return false
	} else if t.p.ExpirationTime == 0 {
		return false
	}

	unixNow := now.Unix()
	if unixNow < t.p.IssuedAt {
		return false
	} else if unixNow >= t.p.ExpirationTime {
		return false
	} else if t.p.NotBefore != 0 && unixNow < t.p.NotBefore {
		return false
	}
	return true
}

// DeleteCookie removes the package cookie associated with the Token.
func (t *Token) DeleteCookie(w http.ResponseWriter) {
	DeleteCookie(w)
}

// Header is a helper function
func (t *Token) Header() string {
	return t.h.b64
}

// Payload is a helper function
func (t *Token) Payload() string {
	return t.p.b64
}

// SetCookie sends the Token to the client in the package cookie. The cookie
// expires no later than the Token. A nil or already-expired Token deletes the
// cookie.
func (t *Token) SetCookie(w http.ResponseWriter) {
	SetCookie(w, t)
}

// Signature is a helper function
func (t *Token) Signature() string {
	return t.s
}

// String implements the Stringer interface.
// Please don't call this before signing the token.
func (t *Token) String() string {
	return t.Header() + "." + t.Payload() + "." + t.Signature()
}
