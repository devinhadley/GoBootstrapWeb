package utils

import (
	"strings"
	"testing"
)

func TestValidateEmailValidInputs(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple address",
			input:    "user@example.com",
			expected: "user@example.com",
		},
		{
			name:     "trims surrounding whitespace",
			input:    "  user@example.com  ",
			expected: "user@example.com",
		},
		{
			name:     "normalizes uppercase domain",
			input:    "user@Example.COM",
			expected: "user@example.com",
		},
		{
			name:     "keeps local part casing",
			input:    "User.Name@Example.COM",
			expected: "User.Name@example.com",
		},
		{
			name:     "allows plus addressing",
			input:    "user+tag@example.com",
			expected: "user+tag@example.com",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ok, normalized := NormalizeAndValidateEmail(tc.input)
			if !ok {
				t.Fatalf("NormalizeAndValidateEmail(%q) returned ok=false, want ok=true", tc.input)
			}

			if normalized != tc.expected {
				t.Fatalf("NormalizeAndValidateEmail(%q) returned %q, want %q", tc.input, normalized, tc.expected)
			}
		})
	}
}

func TestValidateEmailInvalidInputs(t *testing.T) {
	testCases := []string{
		"",
		"   ",
		"null",
		"user",
		"user@localhost",
		"user@example",
		"user@.example.com",
		"user@example.com.",
		"user@@example.com",
		"user@",
		"@example.com",
		"User <user@example.com>",
		"user example.com",
		strings.Repeat("a", 255),
	}

	for _, input := range testCases {
		t.Run(input, func(t *testing.T) {
			ok, normalized := NormalizeAndValidateEmail(input)
			if ok {
				t.Fatalf("NormalizeAndValidateEmail(%q) returned ok=true and %q, want ok=false", input, normalized)
			}

			if normalized != "" {
				t.Fatalf("NormalizeAndValidateEmail(%q) returned %q, want empty string", input, normalized)
			}
		})
	}
}
