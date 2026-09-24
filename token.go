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

// IsValid reports whether the Token has a successfully generated or verified
// signature and is valid at the current UTC time. A nil or unsigned Token, or
// one with a zero iat or exp, is invalid. The iat and optional nbf boundaries
// are inclusive: now >= iat and now >= nbf. The exp boundary is exclusive:
// now < exp. A zero nbf imposes no additional boundary.
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

// DeleteCookie writes the package's deletion cookie. The receiver may be nil;
// it is not inspected. w must be non-nil.
func (t *Token) DeleteCookie(w http.ResponseWriter) {
	DeleteCookie(w)
}

// Header returns the token's unpadded raw-URL-base64 header section. It returns
// an empty string for a nil Token or an unsigned Token not yet encoded by Sign.
func (t *Token) Header() string {
	if t == nil {
		return ""
	}
	return t.h.b64
}

// Payload returns the token's unpadded raw-URL-base64 payload section. It
// returns an empty string for a nil Token or an unsigned Token not yet encoded
// by Sign.
func (t *Token) Payload() string {
	if t == nil {
		return ""
	}
	return t.p.b64
}

// SetCookie writes the Token using the package cookie contract documented by
// the package-level SetCookie function. A nil receiver writes a deletion
// cookie. w must be non-nil.
func (t *Token) SetCookie(w http.ResponseWriter) {
	SetCookie(w, t)
}

// Signature returns the token's signature section verbatim. Factory.Sign
// produces unpadded raw-URL-base64; Decode preserves any non-empty signature
// text for later validation. Signature returns an empty string for a nil Token
// or a newly created Token not yet signed.
func (t *Token) Signature() string {
	if t == nil {
		return ""
	}
	return t.s
}

// String returns the compact header.payload.signature representation and
// implements fmt.Stringer. It returns an empty string for a nil Token. A Token
// returned by NewToken has empty encoded sections until Factory.Sign is called
// and must not be transported before then.
func (t *Token) String() string {
	if t == nil {
		return ""
	}
	return t.Header() + "." + t.Payload() + "." + t.Signature()
}
