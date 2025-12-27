package fiberauth

import (
	"github.com/izetmolla/fiberauth/pkg/credentials"
	"github.com/izetmolla/fiberauth/pkg/session"
	"github.com/izetmolla/fiberauth/pkg/tokens"
	"github.com/izetmolla/fiberauth/pkg/validation"
)

// IsValidPassword compares a plain text password with an encrypted password hash.
// Uses bcrypt to safely compare the passwords.
//
// Parameters:
//   - encpw: The encrypted password hash to compare against
//   - pw: The plain text password to verify
//
// Returns:
//   - bool: true if passwords match, false otherwise
func (a *Authorization) IsValidPassword(encpw, pw string) bool {
	return a.passwordManager.IsValidPassword(encpw, pw)
}

// CreatePassword generates a bcrypt hash from a plain text password.
//
// Parameters:
//   - password: The plain text password to hash
//
// Returns:
//   - string: The bcrypt hash of the password
//   - error: Error if hashing fails
func (a *Authorization) CreatePassword(password string) (string, error) {
	return a.passwordManager.HashPassword(password)
}

// CreatePasswordStandalone is a standalone function for password hashing with default cost.
//
// Parameters:
//   - password: The plain text password to hash
//
// Returns:
//   - string: The bcrypt hash of the password
//   - error: Error if hashing fails
func CreatePassword(password string) (string, error) {
	return credentials.CreatePassword(password)
}

// ExtractToken parses and validates a JWT token string.
//
// Parameters:
//   - tokenString: The JWT token string to parse
//
// Returns:
//   - *tokens.RefreshTokenClaims: The parsed token claims
//   - error: Error if token parsing fails
func (a *Authorization) ExtractToken(tokenString string) (*tokens.RefreshTokenClaims, error) {
	return a.tokenManager.ExtractToken(tokenString)
}

// GetUser extracts the user claims from the provided interface.
//
// Parameters:
//   - userInterface: The interface containing user claims (typically from context)
//
// Returns:
//   - *tokens.Claims: Pointer to Claims struct if successful
//   - error: Error if user not found or type assertion fails
func GetUser(userInterface any) (*tokens.Claims, error) {
	return tokens.GetUser(userInterface)
}

// GetUser is a method wrapper for GetUser function.
func (a *Authorization) GetUser(userInterface any) (*tokens.Claims, error) {
	return GetUser(userInterface)
}

// GetLocalUser extracts the user claims from the provided interface with generic type.
func GetLocalUser[T any](userInterface any) (*T, error) {
	return tokens.GetLocalUser[T](userInterface)
}

// Re-export RefreshTokenClaims and Claims types
type (
	RefreshTokenClaims = tokens.RefreshTokenClaims
	Claims             = tokens.Claims
)

// NewValidator creates a new validator instance with default settings.
// This is a convenience wrapper around pkg/validation.NewValidator.
func NewValidator() *validation.Validator {
	return validation.NewValidator()
}

// ValidationError is re-exported from pkg/validation.
type ValidationError = validation.ValidationError

// NewSessionManager creates a new session manager - internal helper.
// Use Authorization methods instead of creating session managers directly.
func NewSessionManager(cookieSessionName, mainDomainName string) *session.Manager {
	return session.NewManager(cookieSessionName, mainDomainName)
}
