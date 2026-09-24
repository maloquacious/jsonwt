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
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// Decode parses data in header.payload.signature form without verifying it.
// Exactly three non-empty sections are required. Decode raw-URL-base64 decodes
// the header and payload, requires each to be a JSON object, and unmarshals the
// package fields. It preserves all three original encoded sections verbatim.
//
// Decode does not decode the signature, compare a signature, check factory
// metadata, or check token times. A successful result is therefore untrusted
// and IsValid returns false until Factory.Validate succeeds. Any framing,
// header, or payload error returns a nil Token and an error matching
// ErrBadToken. Callers should normally use Factory.Parse instead.
func Decode(data string) (*Token, error) {
	sections := strings.Split(data, ".")
	if len(sections) != 3 || len(sections[0]) == 0 || len(sections[1]) == 0 || len(sections[2]) == 0 {
		return nil, ErrBadToken
	}

	var t Token
	t.h.b64 = sections[0]
	t.p.b64 = sections[1]
	t.s = sections[2]

	// the header is base64 encoded JSON
	if rawHeader, err := decode(t.h.b64); err != nil {
		return nil, fmt.Errorf("%w: header: %v", ErrBadToken, err)
	} else if !isJSONObject(rawHeader) {
		return nil, fmt.Errorf("%w: header must be a JSON object", ErrBadToken)
	} else if err = json.Unmarshal(rawHeader, &t.h); err != nil {
		return nil, fmt.Errorf("%w: header: %v", ErrBadToken, err)
	}

	// the payload is base64 encoded JSON
	if rawPayload, err := decode(t.p.b64); err != nil {
		return nil, fmt.Errorf("%w: payload: %v", ErrBadToken, err)
	} else if !isJSONObject(rawPayload) {
		return nil, fmt.Errorf("%w: payload must be a JSON object", ErrBadToken)
	} else if err = json.Unmarshal(rawPayload, &t.p); err != nil {
		return nil, fmt.Errorf("%w: payload: %v", ErrBadToken, err)
	}

	return &t, nil
}

// decode is a helper function for converting a string containing the base64 representation to raw bytes
func decode(raw string) (b []byte, err error) {
	return base64.RawURLEncoding.DecodeString(raw)
}

// encode is a helper function for converting a slice of raw bytes to a string containg the base64 representation
func encode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func isJSONObject(b []byte) bool {
	b = bytes.TrimSpace(b)
	return len(b) != 0 && b[0] == '{'
}
