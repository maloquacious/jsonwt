/*******************************************************************************
jsonwt - JSON Web Tokens
Copyright (c) 2022 Michael D Henderson

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

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
	"errors"
	"testing"
	"time"
)

func TestNewTokenTTL(t *testing.T) {
	tests := []struct {
		name string
		ttl  time.Duration
	}{
		{name: "zero", ttl: 0},
		{name: "negative", ttl: -time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := NewToken(tt.ttl, nil)
			if token != nil {
				t.Errorf("NewToken(%s) token = %v, want nil", tt.ttl, token)
			}
			if !errors.Is(err, ErrInvalid) {
				t.Errorf("NewToken(%s) error = %v, want %v", tt.ttl, err, ErrInvalid)
			}
		})
	}
}

func TestNewTokenLifetime(t *testing.T) {
	const ttl = 5 * time.Minute
	token, err := NewToken(ttl, nil)
	if err != nil {
		t.Fatalf("NewToken(%s) error = %v", ttl, err)
	}

	if got, want := token.p.ExpirationTime-token.p.IssuedAt, int64(ttl/time.Second); got != want {
		t.Errorf("token lifetime = %d seconds, want %d", got, want)
	}
}

func TestTokenIsValidAtTimeBoundaries(t *testing.T) {
	tests := []struct {
		name      string
		now       int64
		issuedAt  int64
		notBefore int64
		expiresAt int64
		want      bool
	}{
		{name: "before issued-at", now: 99, issuedAt: 100, expiresAt: 200, want: false},
		{name: "at issued-at", now: 100, issuedAt: 100, expiresAt: 200, want: true},
		{name: "after issued-at", now: 101, issuedAt: 100, expiresAt: 200, want: true},
		{name: "before not-before", now: 149, issuedAt: 100, notBefore: 150, expiresAt: 200, want: false},
		{name: "at not-before", now: 150, issuedAt: 100, notBefore: 150, expiresAt: 200, want: true},
		{name: "after not-before", now: 151, issuedAt: 100, notBefore: 150, expiresAt: 200, want: true},
		{name: "before expiration", now: 199, issuedAt: 100, expiresAt: 200, want: true},
		{name: "at expiration", now: 200, issuedAt: 100, expiresAt: 200, want: false},
		{name: "after expiration", now: 201, issuedAt: 100, expiresAt: 200, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var token Token
			token.isSigned = true
			token.p.IssuedAt = tt.issuedAt
			token.p.NotBefore = tt.notBefore
			token.p.ExpirationTime = tt.expiresAt

			if got := token.isValidAt(time.Unix(tt.now, 0)); got != tt.want {
				t.Errorf("isValidAt(%d) = %t, want %t", tt.now, got, tt.want)
			}
		})
	}
}
