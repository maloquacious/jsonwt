/*
 * jsonwt - JSON Web Tokens
 * Copyright (c) 2022 Michael D Henderson
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package jsonwt

import "encoding/json"

// Claim decodes the application claim as JSON into v. The Token must currently
// be valid, and v must satisfy the same requirements as json.Unmarshal,
// normally a non-nil pointer.
//
// Claim returns ErrBadToken for a nil receiver, ErrInvalid for an unsigned or
// time-invalid Token, and ErrMissingClaim when the claim field is absent. Claim
// base64 and JSON decoding errors, including invalid destination errors, are
// returned unchanged.
func (t *Token) Claim(v interface{}) error {
	if t == nil {
		return ErrBadToken
	} else if !t.IsValid() {
		return ErrInvalid
	} else if t.p.Claim == "" {
		return ErrMissingClaim
	}
	b, err := decode(t.p.Claim)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// HasClaim reports whether the package-specific claim field is present. It
// does not validate the Token or decode the claim. A nil Token returns false.
func (t *Token) HasClaim() bool {
	return t != nil && t.p.Claim != ""
}
