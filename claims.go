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

// Claim retrieves the private payload from the Token and marshals it into the given variable.
// It returns errors if the Token is not valid, has no private payload, or there's an error unmarshalling the data.
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

// HasClaim returns true if Token has a claim defined in its payload.
// Note: Token.Claim may fail to return a claim if the Token is invalid.
func (t *Token) HasClaim() bool {
	return t != nil && t.p.Claim != ""
}
