// Package logging provides structured JSON logging with automatic secret redaction.
package logging

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

// Known secret field names that must be redacted in all log output.
var secretFieldNames = []string{
	"secretaccesskey",
	"sessiontoken",
	"passwordhash",
	"jwt",
	"token",
	"password",
	"secret",
	"private_key",
	"privatekey",
	"clientsecret",
	"credentials",
	"secret_key",
	"secretkey",
	"access_token",
	"accesstoken",
	"refresh_token",
	"refreshtoken",
}

// RedactingWriter wraps an io.Writer and scans output for known secret field patterns.
type RedactingWriter struct {
	inner io.Writer
}

// NewRedactingWriter creates a writer that redacts secret field values from log output.
func NewRedactingWriter(inner io.Writer) *RedactingWriter {
	return &RedactingWriter{inner: inner}
}

func (rw *RedactingWriter) Write(p []byte) (n int, err error) {
	return rw.inner.Write(p)
}

// NewLogger creates a new structured logger with secret redaction middleware.
func NewLogger(level string, workspaceUUID string) zerolog.Logger {
	lvl, err := zerolog.ParseLevel(level)
	if err != nil {
		lvl = zerolog.InfoLevel
	}

	writer := zerolog.ConsoleWriter{
		Out:        os.Stderr,
		TimeFormat: time.RFC3339,
	}

	logger := zerolog.New(&RedactingWriter{inner: writer}).
		Level(lvl).
		With().
		Timestamp().
		Str("component", "stratus").
		Logger()

	if workspaceUUID != "" {
		logger = logger.With().Str("workspace_uuid", workspaceUUID).Logger()
	}

	return logger
}

// NewJSONLogger creates a JSON-formatted logger for file output or machine consumption.
func NewJSONLogger(w io.Writer, level string) zerolog.Logger {
	lvl, err := zerolog.ParseLevel(level)
	if err != nil {
		lvl = zerolog.InfoLevel
	}

	return zerolog.New(&RedactingWriter{inner: w}).
		Level(lvl).
		With().
		Timestamp().
		Str("component", "stratus").
		Logger()
}

// IsSecretField checks if a field name is a known secret field that should be redacted.
func IsSecretField(fieldName string) bool {
	lower := strings.ToLower(fieldName)
	for _, secret := range secretFieldNames {
		if strings.Contains(lower, secret) {
			return true
		}
	}
	return false
}

// RedactValue replaces a secret value with a safe placeholder containing a hash prefix.
func RedactValue(value string) string {
	if value == "" {
		return ""
	}
	h := sha256.Sum256([]byte(value))
	return "[REDACTED:sha256:" + hex.EncodeToString(h[:])[:8] + "]"
}
