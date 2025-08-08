package fiberauth

import (
	"errors"
	"fmt"

	"github.com/gofiber/fiber/v3"
)

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

// ErrorJSON creates a standardized error response in JSON format.
// This function formats errors for consistent API responses.
//
// Parameters:
//   - err: The error to format
//   - field: Optional field name that caused the error
//
// Returns:
//   - fiber.Map: Formatted error response
//
// Example:
//
//	errorResponse := auth.ErrorJSON(errors.New("invalid email"), "email")
//	// Returns: fiber.Map{"error": fiber.Map{"message": "invalid email", "field": "email"}}
func (a *Authorization) ErrorJSON(err error, field ...string) fiber.Map {
	message := ""
	if err != nil {
		message = err.Error()
	}
	errJSON := fiber.Map{"error": fiber.Map{"message": message}}
	if len(field) > 0 {
		errJSON["error"].(fiber.Map)["field"] = field[0]
	}
	return errJSON
}

// JSONErrorString creates a JSON error string for error responses.
// This function formats errors as JSON strings for consistent error handling.
//
// Parameters:
//   - message: The error message to format
//
// Returns:
//   - string: JSON formatted error string
//
// Example:
//
//	errorString := auth.JSONErrorString(errors.New("invalid token"))
//	// Returns: `{"error":{"message":"invalid token"}}`
func (a *Authorization) JSONErrorString(message error) string {
	jsonBytes, err := json.Marshal(a.ErrorJSON(err))
	if err != nil {
		// fallback in case of error during marshaling
		return `{"error":{"message":"internal error"}}`
	}
	return string(jsonBytes)
}
