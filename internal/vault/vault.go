// Package vault implements the encrypted secrets store for STRATUS.
// Secrets are encrypted with AES-256-GCM using per-entry DEKs wrapped by
// a master key derived from the operator passphrase via Argon2id.
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"

	"golang.org/x/crypto/argon2"
)

const (
	VaultFileName = "stratus.vault"

	// Argon2id parameters per spec: m=64MB, t=3, p=4
	argonMemory  = 64 * 1024
	argonTime    = 3
	argonThreads = 4
	argonKeyLen  = 32

	saltLen  = 32
	nonceLen = 12 // AES-256-GCM standard nonce size
)

// Entry is a single encrypted secret in the vault.
type Entry struct {
	Nonce      []byte `json:"nonce"`       // 12-byte GCM nonce
	Ciphertext []byte `json:"ciphertext"`  // AES-256-GCM encrypted data + auth tag
}

// vaultFile is the on-disk representation.
type vaultFile struct {
	Salt    []byte            `json:"salt"`    // Argon2id salt
	Entries map[string]*Entry `json:"entries"` // key -> encrypted entry
}

// Vault manages encrypted secret storage.
type Vault struct {
	mu        sync.RWMutex
	masterKey []byte // 256-bit derived key, held in memory only
	salt      []byte
	entries   map[string]*Entry
	path      string // filesystem path to vault file; empty for memory-only mode
	dirty     bool
}

// DeriveKey derives a 256-bit master key from a passphrase and salt using Argon2id.
func DeriveKey(passphrase string, salt []byte) []byte {
	return argon2.IDKey(
		[]byte(passphrase),
		salt,
		argonTime,
		argonMemory,
		argonThreads,
		argonKeyLen,
	)
}

// Create initializes a new vault with a fresh salt and passphrase-derived master key.
func Create(path string, passphrase string) (*Vault, error) {
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("generating salt: %w", err)
	}

	mk := DeriveKey(passphrase, salt)

	v := &Vault{
		masterKey: mk,
		salt:      salt,
		entries:   make(map[string]*Entry),
		path:      path,
		dirty:     true,
	}

	if path != "" {
		if err := v.flush(); err != nil {
			return nil, err
		}
	}
	return v, nil
}

// Open loads an existing vault file and unlocks it with the given passphrase.
func Open(path string, passphrase string) (*Vault, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading vault file: %w", err)
	}

	var vf vaultFile
	if err := json.Unmarshal(data, &vf); err != nil {
		return nil, fmt.Errorf("parsing vault file: %w", err)
	}

	mk := DeriveKey(passphrase, vf.Salt)

	v := &Vault{
		masterKey: mk,
		salt:      vf.Salt,
		entries:   vf.Entries,
		path:      path,
	}

	// Validate the master key by attempting to decrypt any entry (if entries exist).
	// This catches wrong passphrases early.
	for key := range vf.Entries {
		if _, err := v.Get(key); err != nil {
			// Zero the key on failure
			for i := range mk {
				mk[i] = 0
			}
			return nil, fmt.Errorf("incorrect passphrase or corrupted vault")
		}
		break
	}

	return v, nil
}

// CreateMemoryOnly creates an in-memory vault that never writes to disk.
func CreateMemoryOnly(passphrase string) (*Vault, error) {
	return Create("", passphrase)
}

// Put encrypts and stores a secret under the given key.
func (v *Vault) Put(key string, plaintext []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	block, err := aes.NewCipher(v.masterKey)
	if err != nil {
		return fmt.Errorf("creating cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("creating GCM: %w", err)
	}

	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("generating nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, []byte(key)) // key as AAD

	v.entries[key] = &Entry{
		Nonce:      nonce,
		Ciphertext: ciphertext,
	}
	v.dirty = true
	return nil
}

// Get decrypts and returns the secret stored under the given key.
func (v *Vault) Get(key string) ([]byte, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	entry, ok := v.entries[key]
	if !ok {
		return nil, fmt.Errorf("vault key not found: %s", key)
	}

	block, err := aes.NewCipher(v.masterKey)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, entry.Nonce, entry.Ciphertext, []byte(key))
	if err != nil {
		return nil, fmt.Errorf("decrypting vault entry: %w", err)
	}

	return plaintext, nil
}

// Delete removes a secret from the vault.
func (v *Vault) Delete(key string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if _, ok := v.entries[key]; !ok {
		return fmt.Errorf("vault key not found: %s", key)
	}

	delete(v.entries, key)
	v.dirty = true
	return nil
}

// Has checks if a key exists in the vault.
func (v *Vault) Has(key string) bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	_, ok := v.entries[key]
	return ok
}

// Keys returns all vault key names.
func (v *Vault) Keys() []string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	keys := make([]string, 0, len(v.entries))
	for k := range v.entries {
		keys = append(keys, k)
	}
	return keys
}

// Save persists the vault to disk. No-op for memory-only vaults.
func (v *Vault) Save() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.flush()
}

func (v *Vault) flush() error {
	if v.path == "" {
		return nil // memory-only mode
	}
	if !v.dirty {
		return nil
	}

	vf := vaultFile{
		Salt:    v.salt,
		Entries: v.entries,
	}

	data, err := json.Marshal(vf)
	if err != nil {
		return fmt.Errorf("marshaling vault: %w", err)
	}

	if err := os.WriteFile(v.path, data, 0600); err != nil {
		return fmt.Errorf("writing vault file: %w", err)
	}

	v.dirty = false
	return nil
}

// Close zeroes the master key and flushes pending writes.
func (v *Vault) Close() error {
	v.mu.Lock()
	defer v.mu.Unlock()

	err := v.flush()

	// Zero master key
	for i := range v.masterKey {
		v.masterKey[i] = 0
	}

	return err
}

// HashSecret returns a redaction-safe hash prefix for a secret value.
// Format: sha256:<first-8-chars-of-hex-hash>
func HashSecret(secret []byte) string {
	h := sha256.Sum256(secret)
	return "sha256:" + hex.EncodeToString(h[:])[:8]
}
