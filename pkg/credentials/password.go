// Package credentials provides credential management functionality.
// This package isolates password hashing to prevent importing bcrypt unnecessarily.
package credentials

import (
	"golang.org/x/crypto/bcrypt"
)

// PasswordManager handles password hashing and validation operations.
type PasswordManager struct {
	cost int
}

// NewPasswordManager creates a new password manager with the specified cost.
//
// Parameters:
//   - cost: The bcrypt cost factor (4-31, recommended 10-14)
//
// Returns:
//   - *PasswordManager: Password manager instance
func NewPasswordManager(cost int) *PasswordManager {
	if cost == 0 {
		cost = 12 // Default bcrypt cost
	}
	return &PasswordManager{cost: cost}
}

// HashPassword generates a bcrypt hash from a plain text password.
//
// Parameters:
//   - password: The plain text password to hash
//
// Returns:
//   - string: The bcrypt hash of the password
//   - error: Error if hashing fails
func (pm *PasswordManager) HashPassword(password string) (string, error) {
	encpw, err := bcrypt.GenerateFromPassword([]byte(password), pm.cost)
	if err != nil {
		return "", err
	}
	return string(encpw), nil
}

// IsValidPassword compares a plain text password with an encrypted password hash.
// Uses bcrypt to safely compare the passwords.
//
// Parameters:
//   - encpw: The encrypted password hash to compare against
//   - pw: The plain text password to verify
//
// Returns:
//   - bool: true if passwords match, false otherwise
func (pm *PasswordManager) IsValidPassword(encpw, pw string) bool {
	return bcrypt.CompareHashAndPassword([]byte(encpw), []byte(pw)) == nil
}

// CreatePassword is a standalone function for password hashing with default cost.
//
// Parameters:
//   - password: The plain text password to hash
//
// Returns:
//   - string: The bcrypt hash of the password
//   - error: Error if hashing fails
func CreatePassword(password string) (string, error) {
	encpw, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return "", err
	}
	return string(encpw), nil
}

