package pseudonymstore_test

import (
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/zalando/go-keyring"

	"github.com/FullFran/veil/internal/pseudonymstore"
)

// TestOSKeyring_Integration is the one test that talks to the real OS
// keyring. It is opt-in (VEIL_TEST_REAL_KEYRING=1) so the default suite
// never touches it, uses a throwaway service name, deletes its entry, and
// skips when no keyring is reachable (a headless box).
func TestOSKeyring_Integration(t *testing.T) {
	if os.Getenv("VEIL_TEST_REAL_KEYRING") != "1" {
		t.Skip("set VEIL_TEST_REAL_KEYRING=1 to run against the real OS keyring")
	}
	kr := pseudonymstore.OSKeyring{}
	service := fmt.Sprintf("veil-test-%d", time.Now().UnixNano())

	_, err := kr.Get(service, "probe")
	switch {
	case errors.Is(err, pseudonymstore.ErrKeyringNotFound):
	case err != nil:
		t.Skipf("no OS keyring reachable: %v", err)
	default:
		t.Fatal("a fresh service already holds a secret")
	}

	t.Cleanup(func() { keyring.Delete(service, "probe") })
	if err := kr.Set(service, "probe", "value"); err != nil {
		t.Fatalf("Set failed: %v", err)
	}
	got, err := kr.Get(service, "probe")
	if err != nil || got != "value" {
		t.Fatalf("Get = (%q, %v), want (value, nil)", got, err)
	}
}
