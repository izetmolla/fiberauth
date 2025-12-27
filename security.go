package fiberauth

import (
	"crypto/subtle"
	"strings"
	"time"
)

// SecurityConfig holds security-related configuration
type SecurityConfig struct {
	// MaxLoginAttempts is the maximum number of failed login attempts before lockout
	MaxLoginAttempts int

	// LockoutDuration is how long to lock out a user after max attempts
	LockoutDuration time.Duration

	// RequirePasswordStrength enforces password complexity requirements
	RequirePasswordStrength bool

	// AllowedIPRanges restricts access to specific IP ranges (optional)
	AllowedIPRanges []string
}

// DefaultSecurityConfig returns security configuration with safe defaults
func DefaultSecurityConfig() *SecurityConfig {
	return &SecurityConfig{
		MaxLoginAttempts:        5,
		LockoutDuration:         15 * time.Minute,
		RequirePasswordStrength: true,
		AllowedIPRanges:         nil, // No IP restrictions by default
	}
}

// ConstantTimeCompare compares two strings in constant time to prevent timing attacks
func ConstantTimeCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// SecureHeaders returns recommended security headers for HTTP responses
func SecureHeaders() map[string]string {
	return map[string]string{
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"X-XSS-Protection":          "1; mode=block",
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
		"Content-Security-Policy":   "default-src 'self'",
		"Referrer-Policy":           "strict-origin-when-cross-origin",
	}
}

// SanitizeForLog removes sensitive information from strings for safe logging
func SanitizeForLog(s string) string {
	if len(s) <= 4 {
		return "****"
	}
	return s[:2] + strings.Repeat("*", len(s)-4) + s[len(s)-2:]
}
