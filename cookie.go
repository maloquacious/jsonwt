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

// DeleteCookie is a helper function to delete a Cookie that may contain the Token.
func DeleteCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "jsonwt",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
}

// SetCookie is a helper function to create a Cookie containing the Token.
func SetCookie(w http.ResponseWriter, t *Token) {
	var maxAge int
	if t.p.ExpirationTime != 0 {
		maxAge = int(time.Unix(t.p.ExpirationTime, 0).Sub(time.Now().UTC()).Seconds())
	}
	if maxAge < 15 {
		maxAge = 15
	} else if maxAge > 14*24*60*60 {
		maxAge = 14 * 24 * 60 * 60
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "jsonwt",
		Path:     "/",
		Value:    t.String(),
		MaxAge:   maxAge,
		HttpOnly: true,
	})
}
