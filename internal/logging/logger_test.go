package logging

import (
	"strings"
	"testing"
)

func TestIsSecretField(t *testing.T) {
	tests := []struct {
		name     string
		field    string
		expected bool
	}{
		{"secret access key", "SecretAccessKey", true},
		{"session token", "SessionToken", true},
		{"password", "password", true},
		{"password hash", "PasswordHash", true},
		{"jwt", "jwt", true},
		{"private key", "private_key", true},
		{"client secret", "ClientSecret", true},
		{"access key id", "AccessKeyId", false},
		{"username", "username", false},
		{"region", "region", false},
		{"role arn", "RoleArn", false},
		{"nested secret", "aws_secret_key", true},
		{"token field", "refresh_token", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsSecretField(tt.field)
			if got != tt.expected {
				t.Errorf("IsSecretField(%q) = %v, want %v", tt.field, got, tt.expected)
			}
		})
	}
}

func TestRedactValue(t *testing.T) {
	result := RedactValue("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	if !strings.HasPrefix(result, "[REDACTED:sha256:") {
		t.Errorf("Expected [REDACTED:sha256:...], got %s", result)
	}
	if !strings.HasSuffix(result, "]") {
		t.Errorf("Expected trailing ], got %s", result)
	}

	// Same input should produce same hash
	result2 := RedactValue("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	if result != result2 {
		t.Error("Same input should produce same redacted value")
	}

	// Different input should produce different hash
	result3 := RedactValue("differentSecret")
	if result == result3 {
		t.Error("Different inputs should produce different redacted values")
	}
}

func TestRedactEmptyValue(t *testing.T) {
	result := RedactValue("")
	if result != "" {
		t.Errorf("Empty input should return empty, got %q", result)
	}
}
