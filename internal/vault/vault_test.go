package vault

import (
	"os"
	"path/filepath"
	"testing"
)

func TestVaultCreateAndRetrieve(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, VaultFileName)

	v, err := Create(path, "testpassphrase123")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Store a secret
	secret := []byte("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	if err := v.Put("identity:test-uuid", secret); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Retrieve it
	got, err := v.Get("identity:test-uuid")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != string(secret) {
		t.Fatalf("Got %q, want %q", got, secret)
	}

	// Save and close
	if err := v.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Reopen with correct passphrase
	v2, err := Open(path, "testpassphrase123")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer v2.Close()

	got2, err := v2.Get("identity:test-uuid")
	if err != nil {
		t.Fatalf("Get after reopen: %v", err)
	}
	if string(got2) != string(secret) {
		t.Fatalf("After reopen: got %q, want %q", got2, secret)
	}
}

func TestVaultWrongPassphrase(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, VaultFileName)

	v, err := Create(path, "correctpassphrase")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := v.Put("test-key", []byte("secret-data")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	v.Close()

	// Try opening with wrong passphrase
	_, err = Open(path, "wrongpassphrase")
	if err == nil {
		t.Fatal("Expected error with wrong passphrase, got nil")
	}
}

func TestVaultMemoryOnly(t *testing.T) {
	v, err := CreateMemoryOnly("testpass")
	if err != nil {
		t.Fatalf("CreateMemoryOnly: %v", err)
	}

	if err := v.Put("key1", []byte("value1")); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, err := v.Get("key1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "value1" {
		t.Fatalf("Got %q, want %q", got, "value1")
	}

	// Verify no file was created
	if v.path != "" {
		t.Fatal("Memory-only vault should have empty path")
	}

	v.Close()
}

func TestVaultDelete(t *testing.T) {
	v, err := CreateMemoryOnly("testpass")
	if err != nil {
		t.Fatalf("CreateMemoryOnly: %v", err)
	}
	defer v.Close()

	v.Put("key1", []byte("value1"))
	v.Put("key2", []byte("value2"))

	if !v.Has("key1") {
		t.Fatal("Expected key1 to exist")
	}

	if err := v.Delete("key1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	if v.Has("key1") {
		t.Fatal("key1 should be deleted")
	}

	// key2 should still exist
	got, err := v.Get("key2")
	if err != nil {
		t.Fatalf("Get key2: %v", err)
	}
	if string(got) != "value2" {
		t.Fatalf("Got %q, want %q", got, "value2")
	}
}

func TestVaultKeys(t *testing.T) {
	v, err := CreateMemoryOnly("testpass")
	if err != nil {
		t.Fatalf("CreateMemoryOnly: %v", err)
	}
	defer v.Close()

	v.Put("alpha", []byte("a"))
	v.Put("beta", []byte("b"))
	v.Put("gamma", []byte("c"))

	keys := v.Keys()
	if len(keys) != 3 {
		t.Fatalf("Expected 3 keys, got %d", len(keys))
	}
}

func TestHashSecret(t *testing.T) {
	h1 := HashSecret([]byte("secret1"))
	h2 := HashSecret([]byte("secret2"))
	h3 := HashSecret([]byte("secret1"))

	if h1 == h2 {
		t.Fatal("Different secrets should have different hashes")
	}
	if h1 != h3 {
		t.Fatal("Same secret should produce same hash")
	}

	// Verify format
	if len(h1) < 15 {
		t.Fatalf("Hash too short: %s", h1)
	}
}

func TestVaultFilePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, VaultFileName)

	v, err := Create(path, "testpassphrase123")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	v.Put("key", []byte("val"))
	v.Close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}

	// Verify file is mode 0600 (owner read/write only)
	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Fatalf("Expected permissions 0600, got %o", perm)
	}
}
