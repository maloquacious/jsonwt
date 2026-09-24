package jsonwt

import (
	"context"
	"testing"
)

func TestTokenContextRoundTrip(t *testing.T) {
	token := &Token{}
	parent := context.WithValue(context.Background(), contextTestKey{}, "parent value")
	ctx := token.NewContext(parent)

	got, ok := FromContext(ctx)
	if !ok {
		t.Fatal("FromContext() ok = false, want true")
	}
	if got != token {
		t.Errorf("FromContext() token = %p, want %p", got, token)
	}
	if got := ctx.Value(contextTestKey{}); got != "parent value" {
		t.Errorf("parent context value = %v, want %q", got, "parent value")
	}
}

func TestTokenContextMissingAndNil(t *testing.T) {
	tests := []struct {
		name string
		ctx  context.Context
	}{
		{name: "background", ctx: context.Background()},
		{name: "nil context", ctx: nil},
		{name: "nil token", ctx: (*Token)(nil).NewContext(context.Background())},
		{name: "nil token and context", ctx: (*Token)(nil).NewContext(nil)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := FromContext(tt.ctx)
			if got != nil || ok {
				t.Errorf("FromContext() = (%v, %t), want (nil, false)", got, ok)
			}
		})
	}
}

type contextTestKey struct{}
