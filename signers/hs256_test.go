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

package signers

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"testing"
)

func TestNewHS256RejectsEmptySecret(t *testing.T) {
	for _, secret := range [][]byte{nil, {}} {
		signer, err := NewHS256(secret)
		if signer != nil {
			t.Errorf("NewHS256(%v) signer = %v, want nil", secret, signer)
		}
		if !errors.Is(err, ErrEmptySecret) {
			t.Errorf("NewHS256(%v) error = %v, want %v", secret, err, ErrEmptySecret)
		}
	}
}

func TestConstantError(t *testing.T) {
	const errValue = ErrEmptySecret
	if ErrEmptySecret != errValue {
		t.Errorf("ErrEmptySecret = %v, want %v", ErrEmptySecret, errValue)
	}
	if got, want := ErrEmptySecret.Error(), "empty secret"; got != want {
		t.Errorf("ErrEmptySecret.Error() = %q, want %q", got, want)
	}
	if !errors.Is(ErrEmptySecret, errValue) {
		t.Errorf("errors.Is(%v, %v) = false, want true", ErrEmptySecret, errValue)
	}
}

func TestHS256(t *testing.T) {
	secret := []byte("secret")
	signer, err := NewHS256(secret)
	if err != nil {
		t.Fatalf("NewHS256() error = %v", err)
	}
	secret[0] = 'X'

	message := []byte("header.payload")
	got, err := signer.Sign(message)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	h := hmac.New(sha256.New, []byte("secret"))
	_, _ = h.Write(message)
	want := h.Sum(nil)
	if !hmac.Equal(got, want) {
		t.Errorf("Sign() = %x, want %x", got, want)
	}
	if got := signer.Algorithm(); got != "HS256" {
		t.Errorf("Algorithm() = %q, want %q", got, "HS256")
	}
}
