package fiberauth

import (
	"errors"
	"fmt"
	"strings"
)

// ValidationError represents a validation error with field information
type ValidationError struct {
	Field   string
	Message string
}

func (v *ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", v.Field, v.Message)
}

// Validator handles common validation operations
type Validator struct{}

// NewValidator creates a new validator instance
func NewValidator() *Validator {
	return &Validator{}
}

// ValidateRequired validates that a field is not empty
func (v *Validator) ValidateRequired(value, fieldName string) error {
	if strings.TrimSpace(value) == "" {
		return &ValidationError{Field: fieldName, Message: fmt.Sprintf("%s is required", fieldName)}
	}
	return nil
}

// ValidateEmail validates email format
func (v *Validator) ValidateEmail(email string) error {
	if email == "" {
		return &ValidationError{Field: "email", Message: "email is required"}
	}
	
	// Basic email validation
	if !strings.Contains(email, "@") || !strings.Contains(email, ".") {
		return &ValidationError{Field: "email", Message: "invalid email format"}
	}
	
	// Split email into local and domain parts
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return &ValidationError{Field: "email", Message: "invalid email format"}
	}
	
	localPart := parts[0]
	domainPart := parts[1]
	
	// Check if local part is empty
	if strings.TrimSpace(localPart) == "" {
		return &ValidationError{Field: "email", Message: "invalid email format"}
	}
	
	// Check if domain part is empty or doesn't contain a dot
	if strings.TrimSpace(domainPart) == "" || !strings.Contains(domainPart, ".") {
		return &ValidationError{Field: "email", Message: "invalid email format"}
	}
	
	return nil
}

// ValidatePassword validates password strength
func (v *Validator) ValidatePassword(password string) error {
	if password == "" {
		return &ValidationError{Field: "password", Message: "password is required"}
	}
	
	if len(password) < 6 {
		return &ValidationError{Field: "password", Message: "password must be at least 6 characters"}
	}
	
	return nil
}

// ValidateSignUpRequest validates all required fields in SignUpRequest
func (v *Validator) ValidateSignUpRequest(request *SignUpRequest) *ErrorFields {
	validator := NewValidator()
	
	if err := validator.ValidateRequired(request.FirstName, "first_name"); err != nil {
		return &ErrorFields{Error: err, Field: "first_name"}
	}
	
	if err := validator.ValidateRequired(request.LastName, "last_name"); err != nil {
		return &ErrorFields{Error: err, Field: "last_name"}
	}
	
	if err := validator.ValidateEmail(request.Email); err != nil {
		return &ErrorFields{Error: err, Field: "email"}
	}
	
	if err := validator.ValidatePassword(request.Password); err != nil {
		return &ErrorFields{Error: err, Field: "password"}
	}
	
	return nil
}

// ValidateSignInRequest validates all required fields in SignInRequest
func (v *Validator) ValidateSignInRequest(request *SignInRequest) *ErrorFields {
	validator := NewValidator()
	
	// Either email or username must be provided
	if request.Email == "" && request.Username == "" {
		return &ErrorFields{Error: errors.New("email or username is required"), Field: "email"}
	}
	
	if err := validator.ValidatePassword(request.Password); err != nil {
		return &ErrorFields{Error: err, Field: "password"}
	}
	
	return nil
}
