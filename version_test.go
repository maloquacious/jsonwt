package jsonwt_test

import (
	"testing"

	"github.com/mdhender/jsonwt"
)

func TestVersion(t *testing.T) {
	if got, want := jsonwt.Version(), "0.1.0"; got != want {
		t.Errorf("Version() = %q, want %q", got, want)
	}
}
