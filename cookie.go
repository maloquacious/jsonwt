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

const cookieName = "jsonwt"

// DeleteCookie writes a deletion cookie named "jsonwt". The cookie has an
// empty value, Path "/", HttpOnly true, Expires at Unix second 1, and MaxAge
// -1. Domain, Secure, and SameSite retain their net/http zero values. w must be
// non-nil.
func DeleteCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Path:     "/",
		Expires:  time.Unix(1, 0).UTC(),
		MaxAge:   -1,
		HttpOnly: true,
	})
}

// SetCookie writes t in a cookie named "jsonwt". For a usable future exp, the
// cookie has Path "/", Value t.String(), Expires equal to exp, HttpOnly true,
// and MaxAge equal to the whole seconds remaining at call time. It uses the
// Factory clock associated with t, or the system clock when t has no associated
// clock. Domain, Secure, and SameSite retain their net/http zero values.
//
// SetCookie writes the deletion cookie described by DeleteCookie when t is nil,
// exp is missing or elapsed, or less than one whole second remains. It does not
// otherwise validate t. w must be non-nil.
func SetCookie(w http.ResponseWriter, t *Token) {
	setCookie(w, t, t.now())
}

func setCookie(w http.ResponseWriter, t *Token, now time.Time) {
	if t == nil || t.p.ExpirationTime <= now.Unix() {
		DeleteCookie(w)
		return
	}
	expires := time.Unix(t.p.ExpirationTime, 0).UTC()
	maxAge := int(expires.Sub(now) / time.Second)
	if maxAge <= 0 {
		DeleteCookie(w)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Path:     "/",
		Value:    t.String(),
		Expires:  expires,
		MaxAge:   maxAge,
		HttpOnly: true,
	})
}
