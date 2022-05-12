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

// Package signers implements jsonwt.Signer types.
package signers

import (
	"crypto/hmac"
	"crypto/sha256"
)

// HS256 implements the jsonwt.Signer interface using HMAC256.
type HS256 struct {
	key []byte
}

// NewHS256 returns a new HMAC256 signer.
func NewHS256(secret []byte) (*HS256, error) {
	s := HS256{key: make([]byte, len(secret))}
	copy(s.key, secret)
	return &s, nil
}

// Algorithm implements the jsonwt.Signer interface.
// It returns the "name" of the algorithm used for signing messages.
func (s *HS256) Algorithm() string {
	return "HS256"
}

// Sign implements the jsonwt.Signer interface.
// It returns a slice of bytes containing the signature for the message.
func (s *HS256) Sign(msg []byte) ([]byte, error) {
	hm := hmac.New(sha256.New, s.key)
	if _, err := hm.Write(msg); err != nil {
		return nil, err
	}
	return hm.Sum(nil), nil
}
