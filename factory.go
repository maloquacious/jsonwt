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
	"encoding/json"
	"time"
)

// NewFactory returns an initialized factory.
// The signer is used to sign the generated tokens.
// Factories are cheap, so create a new one to rotate keys.
func NewFactory(kid string, s Signer) *Factory {
	return &Factory{kid: kid, s: s}
}

type Factory struct {
	kid string
	s   Signer
}

// ID returns the id of the current signer.
func (f *Factory) ID() string {
	return f.kid
}

// Sign will sign a Token.
// It uses the current values in the header and payload, so it is safe to call multiple times.
// It updates the Token's Algorithm field to match the factory's signer's algorithm.
// It updates the Token's KeyID field to match the factory's key id.
func (f *Factory) Sign(t *Token) error {
	t.isSigned = false // unset the signed flag, just to be safe

	if f == nil || f.kid == "" || f.s == nil {
		return ErrBadFactory
	} else if t == nil {
		return ErrInvalid
	}

	t.h.Algorithm = f.s.Algorithm()
	t.h.KeyID = f.kid

	// base64 encode JSON representation of header
	h, err := json.Marshal(t.h)
	if err != nil {
		return err
	}
	t.h.b64 = encode(h)

	// base64 encode JSON representation of payload
	p, err := json.Marshal(t.p)
	if err != nil {
		return err
	}
	t.p.b64 = encode(p)

	// base64 encode JSON representation of signature
	rawSignature, err := f.s.Sign([]byte(t.h.b64 + "." + t.p.b64))
	if err != nil {
		return err
	}
	t.s = encode(rawSignature)

	t.isSigned = true

	return nil
}

// Token is a helper to create a new, signed Token.
// `scope` is the private application payload to add to the Token
func (f *Factory) Token(ttl time.Duration, scope interface{}) (*Token, error) {
	if f == nil || f.kid == "" || f.s == nil {
		return nil, ErrBadFactory
	}

	t, err := NewToken(ttl, scope)
	if err != nil {
		return nil, err
	} else if err = f.Sign(t); err != nil {
		return nil, err
	}

	return t, nil
}

// Validate will return an error if the Token is not properly signed.
// It tries to update the isSigned to true only if the Token is properly signed.
func (f *Factory) Validate(t *Token) error {
	if t == nil {
		return ErrInvalid
	}

	t.isSigned = false // unset the signed flag, just to be safe

	if f == nil || f.kid == "" || f.s == nil {
		return ErrBadFactory
	}

	expectedSignature, err := f.s.Sign([]byte(t.h.b64 + "." + t.p.b64))
	if err != nil {
		return err
	}

	t.isSigned = t.s == encode(expectedSignature)
	if !t.isSigned {
		return ErrUnauthorized
	}

	return nil // valid signature
}
