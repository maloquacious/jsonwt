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
	"crypto/hmac"
	"encoding/json"
	"time"
)

// NewFactory returns a Factory that identifies and signs tokens with kid and s
// and uses the system clock. It always returns a non-nil Factory; configuration
// validation is deferred to Sign, Token, Parse, and Validate, which return
// ErrBadFactory when kid is empty or s is nil. Factories are cheap and contain
// no key-discovery or key-ring behavior, so callers rotate keys by creating and
// selecting a new Factory.
func NewFactory(kid string, s Signer) *Factory {
	return NewFactoryWithClock(kid, s, systemClock{})
}

// Clock supplies the current time used to issue and validate tokens. Clock
// implementations may return a time in any location; Factory converts it to
// UTC before use.
type Clock interface {
	Now() time.Time
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

// NewFactoryWithClock returns a Factory that uses clock to issue and validate
// tokens. It is intended for deterministic tests; production callers should
// normally use NewFactory. A nil clock makes the Factory invalid, causing Sign,
// Token, Parse, and Validate to return ErrBadFactory.
func NewFactoryWithClock(kid string, s Signer, clock Clock) *Factory {
	return &Factory{kid: kid, s: s, clock: clock}
}

// Factory creates, signs, parses, and validates Tokens with one key ID and one
// Signer. A Factory does not discover keys or select among multiple signers.
type Factory struct {
	kid   string
	s     Signer
	clock Clock
}

// ID returns the key ID supplied to NewFactory. A nil Factory has an empty ID.
func (f *Factory) ID() string {
	if f == nil {
		return ""
	}
	return f.kid
}

// Parse decodes data, then validates its algorithm, key ID, signature, and
// lifetime. On success it returns a verified Token. On every error it returns a
// nil Token.
//
// Malformed compact data or signature encoding returns ErrBadToken. An
// algorithm, key ID, or signature mismatch returns ErrUnauthorized. An
// inactive, expired, or incomplete lifetime returns ErrInvalid. A malformed
// input is rejected before factory configuration is checked; otherwise a nil
// or misconfigured Factory returns ErrBadFactory. Signer errors are propagated.
func (f *Factory) Parse(data string) (*Token, error) {
	t, err := Decode(data)
	if err != nil {
		return nil, err
	}
	if err = f.Validate(t); err != nil {
		return nil, err
	}
	return t, nil
}

// Sign encodes and signs t. It sets the token's alg and kid fields from the
// Factory, regenerates the encoded header and payload, and replaces any prior
// signature. Calling Sign repeatedly is safe.
//
// Sign marks t as signed after the Signer succeeds, but does not check its time
// validity. It returns ErrBadFactory for a nil or misconfigured Factory,
// ErrInvalid for a nil Token, and propagates JSON and Signer errors.
func (f *Factory) Sign(t *Token) error {
	if f == nil || f.kid == "" || f.s == nil || f.clock == nil {
		return ErrBadFactory
	} else if t == nil {
		return ErrInvalid
	}

	t.isSigned = false // unset the signed flag, just to be safe

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

// Token creates a Token with NewToken and signs it with the Factory. ttl and
// claim have the semantics documented by NewToken. Token returns ErrBadFactory
// before examining ttl or claim when the Factory is nil or misconfigured. It
// otherwise returns errors from NewToken or Sign unchanged.
func (f *Factory) Token(ttl time.Duration, claim interface{}) (*Token, error) {
	if f == nil || f.kid == "" || f.s == nil || f.clock == nil {
		return nil, ErrBadFactory
	}

	t, err := newToken(ttl, claim, f.clock.Now().UTC())
	if err != nil {
		return nil, err
	} else if err = f.Sign(t); err != nil {
		return nil, err
	}
	t.clock = f.clock

	return t, nil
}

// Validate verifies t's alg and kid against the Factory, decodes and compares
// its signature in constant time, and then checks its lifetime using the
// Factory clock. Successful validation marks t as signed and associates the
// Factory clock with it so IsValid and Claim use the same clock.
//
// A nil Token or invalid lifetime returns ErrInvalid. For a non-nil Token, a
// nil or misconfigured Factory returns ErrBadFactory. A malformed signature
// encoding returns ErrBadToken; metadata or signature mismatches return
// ErrUnauthorized. Signer errors are propagated. Validate always clears any
// prior signed state before checking the token.
func (f *Factory) Validate(t *Token) error {
	if t == nil {
		return ErrInvalid
	}

	t.isSigned = false // unset the signed flag, just to be safe

	if f == nil || f.kid == "" || f.s == nil || f.clock == nil {
		return ErrBadFactory
	}
	if t.h.Algorithm != f.s.Algorithm() || t.h.KeyID != f.kid {
		return ErrUnauthorized
	}

	signature, err := decode(t.s)
	if err != nil {
		return ErrBadToken
	}

	expectedSignature, err := f.s.Sign([]byte(t.h.b64 + "." + t.p.b64))
	if err != nil {
		return err
	}

	t.isSigned = hmac.Equal(signature, expectedSignature)
	if !t.isSigned {
		return ErrUnauthorized
	}
	if !t.isValidAt(f.clock.Now().UTC()) {
		return ErrInvalid
	}
	t.clock = f.clock

	return nil
}
