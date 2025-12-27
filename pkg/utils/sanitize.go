// Package utils provides utility functions for input sanitization and security
package utils

import (
	"strings"
	"unicode"
)

// SanitizeEmail trims whitespace and converts email to lowercase
func SanitizeEmail(email string) string {
	email = strings.TrimSpace(email)
	email = strings.ToLower(email)
	return email
}

// SanitizeUsername trims whitespace and removes invalid characters
func SanitizeUsername(username string) string {
	username = strings.TrimSpace(username)
	// Remove any non-alphanumeric characters except underscore, hyphen, dot
	var builder strings.Builder
	for _, r := range username {
		if unicode.IsLetter(r) || unicode.IsNumber(r) || r == '_' || r == '-' || r == '.' {
			builder.WriteRune(r)
		}
	}
	return builder.String()
}

// SanitizeName trims whitespace from first/last names
func SanitizeName(name string) string {
	return strings.TrimSpace(name)
}

// TruncateString safely truncates a string to maxLength
func TruncateString(s string, maxLength int) string {
	if len(s) <= maxLength {
		return s
	}
	return s[:maxLength]
}

// IsValidEmailFormat performs basic email format validation
func IsValidEmailFormat(email string) bool {
	// Basic checks
	if email == "" {
		return false
	}

	// Must contain exactly one @
	atCount := strings.Count(email, "@")
	if atCount != 1 {
		return false
	}

	// Split by @
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}

	local, domain := parts[0], parts[1]

	// Local part must not be empty
	if len(local) == 0 || len(local) > 64 {
		return false
	}

	// Domain part must contain at least one dot and not be empty
	if len(domain) == 0 || len(domain) > 255 || !strings.Contains(domain, ".") {
		return false
	}

	// Domain must not start or end with dot
	if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return false
	}

	return true
}
