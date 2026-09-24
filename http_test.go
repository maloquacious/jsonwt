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
	"net/http/httptest"
	"testing"
	"time"
)

func TestFromBearerToken(t *testing.T) {
	encoded := newHTTPTestToken(t, "bearer").String()
	tests := []struct {
		name   string
		header string
		want   bool
	}{
		{name: "canonical scheme", header: "Bearer " + encoded, want: true},
		{name: "lowercase scheme", header: "bearer " + encoded, want: true},
		{name: "mixed-case scheme", header: "BeArEr " + encoded, want: true},
		{name: "multiple spaces", header: "Bearer   " + encoded, want: true},
		{name: "missing header"},
		{name: "wrong scheme", header: "Basic " + encoded},
		{name: "missing token", header: "Bearer"},
		{name: "extra field", header: "Bearer " + encoded + " extra"},
		{name: "malformed token", header: "Bearer not-a-token"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.Header.Set("Authorization", tt.header)
			got := FromBearerToken(r)
			if (got != nil) != tt.want {
				t.Fatalf("FromBearerToken() token present = %t, want %t", got != nil, tt.want)
			}
			if got != nil && got.String() != encoded {
				t.Errorf("FromBearerToken() = %q, want %q", got.String(), encoded)
			}
		})
	}
}

func TestCookieRoundTrip(t *testing.T) {
	token := newHTTPTestToken(t, "cookie")
	w := httptest.NewRecorder()
	token.SetCookie(w)

	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("SetCookie() wrote %d cookies, want 1", len(cookies))
	}
	cookie := cookies[0]
	if cookie.Name != cookieName {
		t.Errorf("cookie name = %q, want %q", cookie.Name, cookieName)
	}
	if cookie.Value != token.String() {
		t.Errorf("cookie value = %q, want %q", cookie.Value, token.String())
	}
	if cookie.MaxAge <= 0 {
		t.Errorf("cookie MaxAge = %d, want positive", cookie.MaxAge)
	}
	if cookie.Path != "/" {
		t.Errorf("cookie Path = %q, want %q", cookie.Path, "/")
	}
	if !cookie.HttpOnly {
		t.Error("cookie HttpOnly = false, want true")
	}
	if got, want := cookie.Expires.Unix(), token.p.ExpirationTime; got != want {
		t.Errorf("cookie expiration = %d, want %d", got, want)
	}

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(cookie)
	got := FromCookie(r)
	if got == nil {
		t.Fatal("FromCookie() = nil, want token")
	}
	if got.String() != token.String() {
		t.Errorf("FromCookie() = %q, want %q", got.String(), token.String())
	}

	w = httptest.NewRecorder()
	token.DeleteCookie(w)
	deleted := w.Result().Cookies()
	if len(deleted) != 1 {
		t.Fatalf("DeleteCookie() wrote %d cookies, want 1", len(deleted))
	}
	if deleted[0].Name != cookieName || deleted[0].Value != "" || deleted[0].MaxAge >= 0 {
		t.Errorf("DeleteCookie() cookie = %+v, want empty %q cookie with negative MaxAge", deleted[0], cookieName)
	}
	if deleted[0].Path != "/" || !deleted[0].HttpOnly || !deleted[0].Expires.Before(time.Now()) {
		t.Errorf("DeleteCookie() attributes = %+v, want expired HttpOnly cookie scoped to /", deleted[0])
	}
}

func TestSetCookieExpiration(t *testing.T) {
	clock := &testClock{now: time.Unix(100, 0)}
	f := NewFactoryWithClock("key-1", testSigner("secret"), clock)
	issued, err := f.Token(time.Minute, nil)
	if err != nil {
		t.Fatalf("Token() error = %v", err)
	}
	missingExpiration := &Token{clock: clock}

	tests := []struct {
		name       string
		token      *Token
		now        time.Time
		wantMaxAge int
	}{
		{name: "future expiration", token: issued, now: time.Unix(100, 0), wantMaxAge: 60},
		{name: "less than one second remaining", token: issued, now: time.Unix(159, 500_000_000), wantMaxAge: -1},
		{name: "at expiration", token: issued, now: time.Unix(160, 0), wantMaxAge: -1},
		{name: "after expiration", token: issued, now: time.Unix(161, 0), wantMaxAge: -1},
		{name: "missing expiration", token: missingExpiration, now: time.Unix(100, 0), wantMaxAge: -1},
		{name: "nil token", token: nil, now: time.Unix(100, 0), wantMaxAge: -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clock.now = tt.now

			packageResponse := httptest.NewRecorder()
			SetCookie(packageResponse, tt.token)
			methodResponse := httptest.NewRecorder()
			tt.token.SetCookie(methodResponse)
			if got, want := methodResponse.Header().Get("Set-Cookie"), packageResponse.Header().Get("Set-Cookie"); got != want {
				t.Errorf("Token.SetCookie header = %q, want package SetCookie header %q", got, want)
			}

			cookies := packageResponse.Result().Cookies()
			if len(cookies) != 1 {
				t.Fatalf("SetCookie() wrote %d cookies, want 1", len(cookies))
			}
			cookie := cookies[0]
			if got := cookie.MaxAge; got != tt.wantMaxAge {
				t.Errorf("SetCookie() MaxAge = %d, want %d", got, tt.wantMaxAge)
			}
			if cookie.Name != cookieName || cookie.Path != "/" || !cookie.HttpOnly {
				t.Errorf("SetCookie() attributes = %+v, want named, root-scoped HttpOnly cookie", cookie)
			}
			if tt.wantMaxAge > 0 {
				if got, want := cookie.Expires.Unix(), int64(160); got != want {
					t.Errorf("SetCookie() Expires = %d, want %d", got, want)
				}
				if cookie.Value != issued.String() {
					t.Errorf("SetCookie() Value = %q, want %q", cookie.Value, issued.String())
				}
			} else if cookie.Value != "" || cookie.Expires.Unix() != 1 {
				t.Errorf("SetCookie() deletion attributes = %+v, want empty value expiring at Unix second 1", cookie)
			}
		})
	}
}

func TestSetCookieUsesSystemClockWithoutAssociatedClock(t *testing.T) {
	expiration := time.Now().Add(time.Hour).Unix()
	token := tokenExpiringAt(expiration)
	w := httptest.NewRecorder()
	SetCookie(w, token)

	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("SetCookie() wrote %d cookies, want 1", len(cookies))
	}
	cookie := cookies[0]
	if cookie.MaxAge <= 0 || cookie.MaxAge > int(time.Hour/time.Second) {
		t.Errorf("SetCookie() MaxAge = %d, want positive and at most %d", cookie.MaxAge, int(time.Hour/time.Second))
	}
	if got := cookie.Expires.Unix(); got != expiration {
		t.Errorf("SetCookie() Expires = %d, want %d", got, expiration)
	}
}

func TestHTTPHelpersRejectMalformedCookie(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: cookieName, Value: "not-a-token"})
	if got := FromCookie(r); got != nil {
		t.Errorf("FromCookie() = %v, want nil", got)
	}
}

func TestFromRequestPrecedence(t *testing.T) {
	bearer := newHTTPTestToken(t, "bearer")
	cookie := newHTTPTestToken(t, "cookie")

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+bearer.String())
	r.AddCookie(&http.Cookie{Name: cookieName, Value: cookie.String()})
	if got := FromRequest(r); got == nil || got.String() != bearer.String() {
		t.Errorf("FromRequest() = %v, want bearer token", got)
	}

	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer malformed")
	r.AddCookie(&http.Cookie{Name: cookieName, Value: cookie.String()})
	if got := FromRequest(r); got == nil || got.String() != cookie.String() {
		t.Errorf("FromRequest() with malformed bearer = %v, want cookie token", got)
	}
}

func TestRequestHelpersAcceptNilRequest(t *testing.T) {
	tests := []struct {
		name string
		get  func(*http.Request) *Token
	}{
		{name: "bearer", get: FromBearerToken},
		{name: "cookie", get: FromCookie},
		{name: "request", get: FromRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.get(nil); got != nil {
				t.Errorf("helper(nil) = %v, want nil", got)
			}
		})
	}
}

func newHTTPTestToken(t *testing.T, claim string) *Token {
	t.Helper()
	f := NewFactory("key-1", testSigner("secret"))
	token, err := f.Token(time.Hour, claim)
	if err != nil {
		t.Fatalf("Token() error = %v", err)
	}
	return token
}

func tokenExpiringAt(expiration int64) *Token {
	t := &Token{}
	t.p.ExpirationTime = expiration
	return t
}
