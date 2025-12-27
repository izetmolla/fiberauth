// Package errors provides enhanced error handling with wrapping support
package errors

import "fmt"

// Wrap wraps an error with additional context
func Wrap(err error, message string) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", message, err)
}

// Wrapf wraps an error with formatted context
func Wrapf(err error, format string, args ...interface{}) error {
	if err == nil {
		return nil
	}
	message := fmt.Sprintf(format, args...)
	return fmt.Errorf("%s: %w", message, err)
}

// NewErrorField creates a new ErrorFields with the given error and field
func NewErrorField(err error, field string) *ErrorFields {
	return &ErrorFields{
		Error: err,
		Field: field,
	}
}

// NewErrorMessage creates a new ErrorFields with a custom message
func NewErrorMessage(message, field string) *ErrorFields {
	return &ErrorFields{
		Error: fmt.Errorf("%s", message),
		Field: field,
	}
}

