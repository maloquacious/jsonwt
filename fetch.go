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

// FromBearerToken returns the Token from the Authorization header.
// The Bearer scheme is matched case-insensitively. The token is decoded but
// not verified; callers must validate it before use. If r is nil or the header
// is missing or malformed, FromBearerToken returns nil.
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

// FromCookie returns the Token stored in the package cookie. The token is
// decoded but not verified; callers must validate it before use. If r is nil
// or the cookie is missing or malformed, FromCookie returns nil.
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

// FromRequest returns a decoded Token from r. A valid bearer token takes
// precedence over the package cookie. If the bearer header is absent or
// malformed, FromRequest falls back to the cookie. Callers must validate the
// returned token before use.
func FromRequest(r *http.Request) *Token {
	t := FromBearerToken(r)
	if t == nil {
		t = FromCookie(r)
	}
	return t
}
