// Package validation provides additional validation rules
package validation

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

// PasswordStrength represents password strength levels
type PasswordStrength int

const (
	PasswordWeak PasswordStrength = iota
	PasswordModerate
	PasswordStrong
	PasswordVeryStrong
)

// ValidatePasswordStrength checks password complexity
func (v *Validator) ValidatePasswordStrength(password string, requiredStrength PasswordStrength) error {
	strength := calculatePasswordStrength(password)
	
	if strength < requiredStrength {
		return &ValidationError{
			Field:   "password",
			Message: fmt.Sprintf("password is too weak (required: %v, got: %v)", requiredStrength, strength),
		}
	}
	
	return nil
}

// calculatePasswordStrength calculates password strength
func calculatePasswordStrength(password string) PasswordStrength {
	var (
		hasLower   bool
		hasUpper   bool
		hasNumber  bool
		hasSpecial bool
	)
	
	for _, char := range password {
		switch {
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}
	
	complexity := 0
	if hasLower {
		complexity++
	}
	if hasUpper {
		complexity++
	}
	if hasNumber {
		complexity++
	}
	if hasSpecial {
		complexity++
	}
	
	length := len(password)
	
	switch {
	case complexity >= 4 && length >= 12:
		return PasswordVeryStrong
	case complexity >= 3 && length >= 10:
		return PasswordStrong
	case complexity >= 2 && length >= 8:
		return PasswordModerate
	default:
		return PasswordWeak
	}
}

// ValidateUsername validates username format
func (v *Validator) ValidateUsername(username string) error {
	if username == "" {
		return &ValidationError{Field: "username", Message: "username is required"}
	}
	
	// Username must be 3-30 characters
	if len(username) < 3 {
		return &ValidationError{Field: "username", Message: "username must be at least 3 characters"}
	}
	if len(username) > 30 {
		return &ValidationError{Field: "username", Message: "username must not exceed 30 characters"}
	}
	
	// Username must start with a letter
	if !unicode.IsLetter(rune(username[0])) {
		return &ValidationError{Field: "username", Message: "username must start with a letter"}
	}
	
	// Username can only contain alphanumeric, underscore, hyphen, dot
	validUsername := regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_.-]*$`)
	if !validUsername.MatchString(username) {
		return &ValidationError{Field: "username", Message: "username contains invalid characters"}
	}
	
	return nil
}

// ValidateNotEmpty validates that a string is not empty or whitespace-only
func (v *Validator) ValidateNotEmpty(value, fieldName string) error {
	if strings.TrimSpace(value) == "" {
		return &ValidationError{
			Field:   fieldName,
			Message: fmt.Sprintf("%s cannot be empty", fieldName),
		}
	}
	return nil
}

// ValidateLength validates string length constraints
func (v *Validator) ValidateLength(value, fieldName string, min, max int) error {
	length := len(value)
	
	if length < min {
		return &ValidationError{
			Field:   fieldName,
			Message: fmt.Sprintf("%s must be at least %d characters", fieldName, min),
		}
	}
	
	if max > 0 && length > max {
		return &ValidationError{
			Field:   fieldName,
			Message: fmt.Sprintf("%s must not exceed %d characters", fieldName, max),
		}
	}
	
	return nil
}

