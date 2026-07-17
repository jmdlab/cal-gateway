package proton

import (
	"errors"
	"fmt"
	"testing"

	papi "github.com/ProtonMail/go-proton-api"
)

func TestPrimaryUserKeyID(t *testing.T) {
	t.Run("no keys", func(t *testing.T) {
		if _, err := primaryUserKeyID(papi.User{}); err == nil {
			t.Fatal("expected error for user without keys")
		}
	})

	t.Run("primary flagged", func(t *testing.T) {
		user := papi.User{Keys: papi.Keys{
			{ID: "k1", Primary: false},
			{ID: "k2", Primary: true},
		}}
		id, err := primaryUserKeyID(user)
		if err != nil {
			t.Fatal(err)
		}
		if id != "k2" {
			t.Errorf("got %q, want k2", id)
		}
	})

	t.Run("fallback to first", func(t *testing.T) {
		user := papi.User{Keys: papi.Keys{
			{ID: "k1", Primary: false},
			{ID: "k2", Primary: false},
		}}
		id, err := primaryUserKeyID(user)
		if err != nil {
			t.Fatal(err)
		}
		if id != "k1" {
			t.Errorf("got %q, want k1", id)
		}
	})
}

func TestIsInsufficientScope(t *testing.T) {
	scoped := &papi.APIError{Status: 403, Code: codeInsufficientScope}
	if !isInsufficientScope(scoped) {
		t.Error("code 9101 should be detected")
	}
	if !isInsufficientScope(fmt.Errorf("wrapped: %w", scoped)) {
		t.Error("wrapped 9101 should be detected")
	}
	// A bare 403 (different code) must NOT trigger the SRP dance.
	if isInsufficientScope(&papi.APIError{Status: 403, Code: 9999}) {
		t.Error("bare 403 with another code must not be treated as insufficient scope")
	}
	if isInsufficientScope(errors.New("plain")) {
		t.Error("non-API error must not be treated as insufficient scope")
	}
}
