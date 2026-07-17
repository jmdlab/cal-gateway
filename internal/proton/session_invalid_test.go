package proton

import (
	"errors"
	"os"
	"testing"

	"github.com/jmdlab/cal-gateway/internal/atrest"
)

// TestLoadSealedWrongKeyIsSessionInvalid: an unreadable sealed session (key
// rotated/lost) can never self-heal — it must carry ErrSessionInvalid so serve
// exits 78 (RestartPreventExitStatus) instead of crash-looping forever.
func TestLoadSealedWrongKeyIsSessionInvalid(t *testing.T) {
	dir := t.TempDir()
	if err := SaveSession(dir, sampleSession()); err != nil {
		t.Fatal(err)
	}
	bad := make([]byte, 32)
	if err := os.WriteFile(atrest.KeyPath(dir), bad, 0o600); err != nil {
		t.Fatal(err)
	}
	atrest.ResetCacheForTest()

	_, err := LoadSession(dir)
	if !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("unreadable sealed session must wrap ErrSessionInvalid (exit 78), got: %v", err)
	}
}
