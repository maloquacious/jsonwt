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
	"strings"
)

// FromBearerToken decodes the Token in r's Authorization header. The header
// must contain exactly two whitespace-separated fields; the first must be the
// Bearer scheme, matched case-insensitively, and the second must be a compact
// token accepted by Decode.
//
// FromBearerToken does not verify the token. Callers must use Factory.Validate
// before use. It returns nil when r is nil or the header or token is malformed.
func FromBearerToken(r *http.Request) *Token {
	if r == nil {
		return nil
	}
	authTokens := strings.Fields(r.Header.Get("Authorization"))
	if len(authTokens) != 2 {
		return nil
	}
	authType, authToken := authTokens[0], authTokens[1]
	if !strings.EqualFold(authType, "Bearer") {
		return nil
	}
	j, err := Decode(authToken)
	if err != nil {
		return nil
	}
	return j
}

// FromCookie decodes the Token in r's cookie named "jsonwt". It does not verify
// the token; callers must use Factory.Validate before use. It returns nil when
// r is nil or the cookie is missing or contains a malformed token.
func FromCookie(r *http.Request) *Token {
	if r == nil {
		return nil
	}
	c, err := r.Cookie(cookieName)
	if err != nil {
		return nil
	}
	t, err := Decode(c.Value)
	if err != nil {
		return nil
	}
	return t
}

// FromRequest returns a decoded Token from r. A syntactically decodable bearer
// token takes precedence over the "jsonwt" cookie, even if later validation
// fails. If the bearer header is absent or malformed, FromRequest falls back to
// the cookie. It returns nil for a nil request or when neither source decodes.
// Callers must use Factory.Validate before using the returned token.
func FromRequest(r *http.Request) *Token {
	t := FromBearerToken(r)
	if t == nil {
		t = FromCookie(r)
	}
	return t
}
