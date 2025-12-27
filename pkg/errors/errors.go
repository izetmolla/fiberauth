// Package errors provides standardized error types and handling for authentication.
// This package can be imported without bringing in heavy dependencies like GORM or Redis.
package errors

import "errors"

// ErrorFields represents error information with an optional field identifier.
// This struct is used to provide detailed error information including which field caused the error.
type ErrorFields struct {
	Error error  `json:"error"`           // The error that occurred
	Field string `json:"field,omitempty"` // The field that caused the error (optional)
}

var (
	// ErrInvalidCredentials is returned when user credentials are invalid
	ErrInvalidCredentials = errors.New("invalid credentials")
	// ErrUserNotFound is returned when a user cannot be found
	ErrUserNotFound = errors.New("user not found")
	// ErrUserAlreadyExists is returned when trying to create a user that already exists
	ErrUserAlreadyExists = errors.New("user already exists")
	// ErrInvalidToken is returned when a token is invalid or malformed
	ErrInvalidToken = errors.New("invalid token")
	// ErrTokenExpired is returned when a token has expired
	ErrTokenExpired = errors.New("token expired")
	// ErrUnauthorized is returned when a user is not authorized
	ErrUnauthorized = errors.New("unauthorized")
)

