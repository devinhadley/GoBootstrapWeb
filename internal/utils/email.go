package utils

import (
	"net/mail"
	"strings"
)

// NormalizeAndValidateEmail normalizes email and reports whether the input is valid.
func NormalizeAndValidateEmail(input string) (bool, string) {
	email := strings.TrimSpace(input)

	if email == "" || len(email) > 254 {
		return false, ""
	}

	addr, err := mail.ParseAddress(email)
	if err != nil {
		return false, ""
	}
	if addr.Address != email {
		return false, ""
	}

	if strings.Count(email, "@") != 1 {
		return false, ""
	}

	parts := strings.Split(email, "@")
	local := parts[0]
	domain := parts[1]

	if local == "" || domain == "" {
		return false, ""
	}
	if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return false, ""
	}
	if !strings.Contains(domain, ".") {
		return false, ""
	}

	normalized := local + "@" + strings.ToLower(domain)
	return true, normalized
}
