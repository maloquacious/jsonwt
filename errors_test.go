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

package jsonwt_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/mdhender/jsonwt"
)

const (
	badFactory   = jsonwt.ErrBadFactory
	badToken     = jsonwt.ErrBadToken
	invalid      = jsonwt.ErrInvalid
	missingClaim = jsonwt.ErrMissingClaim
	unauthorized = jsonwt.ErrUnauthorized
)

func TestConstantErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want jsonwt.Error
		text string
	}{
		{name: "bad factory", err: jsonwt.ErrBadFactory, want: badFactory, text: "bad factory"},
		{name: "bad token", err: jsonwt.ErrBadToken, want: badToken, text: "bad token"},
		{name: "invalid", err: jsonwt.ErrInvalid, want: invalid, text: "invalid token"},
		{name: "missing claim", err: jsonwt.ErrMissingClaim, want: missingClaim, text: "missing claim"},
		{name: "unauthorized", err: jsonwt.ErrUnauthorized, want: unauthorized, text: "unauthorized"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err != tt.want {
				t.Fatalf("direct equality: got %v, want %v", tt.err, tt.want)
			}
			if got := tt.err.Error(); got != tt.text {
				t.Errorf("Error() = %q, want %q", got, tt.text)
			}
			if !errors.Is(tt.err, tt.want) {
				t.Errorf("errors.Is(%v, %v) = false, want true", tt.err, tt.want)
			}
			if wrapped := fmt.Errorf("wrapped: %w", tt.err); !errors.Is(wrapped, tt.want) {
				t.Errorf("errors.Is(%v, %v) = false, want true", wrapped, tt.want)
			}
		})
	}
}
