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

// Error is a constant error value.
type Error string

// Error returns the error message.
func (e Error) Error() string { return string(e) }

const (
	// ErrBadFactory indicates that a factory is not configured correctly.
	ErrBadFactory = Error("bad factory")
	// ErrBadToken indicates that a token is malformed.
	ErrBadToken = Error("bad token")
	// ErrInvalid indicates that a token is invalid.
	ErrInvalid = Error("invalid token")
	// ErrMissingClaim indicates that a required claim is absent.
	ErrMissingClaim = Error("missing claim")
	// ErrUnauthorized indicates that token authorization failed.
	ErrUnauthorized = Error("unauthorized")
)
