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
// If there is no bearer token or if the token is invalid for any reason, it returns nil.
func FromBearerToken(r *http.Request) *Token {
	//log.Printf("jsonwt: bearer: entered\n")
	headerAuthText := r.Header.Get("Authorization")
	if headerAuthText == "" {
		return nil
	}
	//log.Printf("jsonwt: bearer: found authorization header\n")
	authTokens := strings.SplitN(headerAuthText, " ", 2)
	if len(authTokens) != 2 {
		return nil
	}
	//log.Printf("jsonwt: bearer: found authorization token\n")
	authType, authToken := authTokens[0], strings.TrimSpace(authTokens[1])
	if authType != "Bearer" {
		return nil
	}
	//log.Printf("jsonwt: bearer: found bearer token\n")
	j, err := Decode(authToken)
	if err != nil {
		//log.Printf("jsonwt: bearer: token: %+v\n", err)
		return nil
	}
	//log.Printf("jsonwt: bearer: returning bearer token\n")
	return j
}

func FromCookie(r *http.Request) *Token {
	//log.Printf("jsonwt: cookie: entered\n")
	c, err := r.Cookie("jwt")
	if err != nil {
		//log.Printf("jsonwt: cookie: %+v\n", err)
		return nil
	}
	t, err := Decode(c.Value)
	if err != nil {
		//log.Printf("jsonwt: cookie: token: %+v\n", err)
		return nil
	}
	return t
}

// FromRequest will pull a Token from a request header.
// It looks for a bearer token first.
// If it can't find one, it looks for a cookie.
func FromRequest(r *http.Request) *Token {
	t := FromBearerToken(r)
	if t == nil {
		t = FromCookie(r)
	}
	return t
}
