package jsonwt

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func TestDecodeRejectsMalformedTokens(t *testing.T) {
	object := base64.RawURLEncoding.EncodeToString([]byte(`{}`))
	valid := object + "." + object + ".c2lnbmF0dXJl"
	tests := []struct {
		name string
		data string
	}{
		{name: "empty input", data: ""},
		{name: "one section", data: object},
		{name: "two sections", data: object + "." + object},
		{name: "four sections", data: valid + ".extra"},
		{name: "empty header", data: "." + object + ".signature"},
		{name: "empty payload", data: object + "..signature"},
		{name: "empty signature", data: object + "." + object + "."},
		{name: "invalid header base64", data: "%." + object + ".signature"},
		{name: "invalid payload base64", data: object + ".%.signature"},
		{name: "invalid header JSON", data: encodedTestSection(`{"alg":`) + "." + object + ".signature"},
		{name: "invalid payload JSON", data: object + "." + encodedTestSection(`{"exp":`) + ".signature"},
		{name: "wrong header field type", data: encodedTestSection(`{"alg":1}`) + "." + object + ".signature"},
		{name: "wrong payload field type", data: object + "." + encodedTestSection(`{"exp":"later"}`) + ".signature"},
	}

	shapes := []string{"null", `"text"`, "[]", "1", "true"}
	for _, shape := range shapes {
		tests = append(tests,
			struct {
				name string
				data string
			}{name: "header shape " + shape, data: encodedTestSection(shape) + "." + object + ".signature"},
			struct {
				name string
				data string
			}{name: "payload shape " + shape, data: object + "." + encodedTestSection(shape) + ".signature"},
		)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Decode(tt.data)
			if got != nil {
				t.Errorf("Decode() token = %v, want nil", got)
			}
			if !errors.Is(err, ErrBadToken) {
				t.Errorf("Decode() error = %v, want %v", err, ErrBadToken)
			}
		})
	}
}

func TestDecodePreservesEncodedSections(t *testing.T) {
	header := encodedTestSection(` {"alg":"HS256","typ":"JWT","kid":"key-1"} `)
	payload := encodedTestSection(` {"iat":1,"exp":2} `)
	signature := "c2lnbmF0dXJl"
	token, err := Decode(strings.Join([]string{header, payload, signature}, "."))
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if token.Header() != header {
		t.Errorf("Header() = %q, want %q", token.Header(), header)
	}
	if token.Payload() != payload {
		t.Errorf("Payload() = %q, want %q", token.Payload(), payload)
	}
	if token.Signature() != signature {
		t.Errorf("Signature() = %q, want %q", token.Signature(), signature)
	}
	if got, want := token.String(), header+"."+payload+"."+signature; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func encodedTestSection(json string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(json))
}
