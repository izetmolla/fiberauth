package fiberauth

import "fmt"

// SignIn authenticates a user with email/username and password.
// Validates credentials and returns tokens and user data upon successful authentication.
//
// Parameters:
//   - request: SignInRequest containing email/username and password
//
// Returns:
//   - *AuthorizationResponse: Response containing tokens, session ID, and user data
//   - *ErrorFields: Error details if authentication fails
//
// Example:
//
//	response, err := auth.SignIn(&SignInRequest{
//	    Email:    "user@example.com",
//	    Password: "password123",
//	})
//	if err != nil {
//	    // Handle authentication error
//	}
func (a *Authorization) LDAPSignIn(request *SignInRequest) (*AuthorizationResponse, *ErrorFields) {
	// Validate request
	validator := NewValidator()
	if err := validator.ValidateSignInRequest(request); err != nil {
		return nil, err
	}

	return nil, &ErrorFields{Error: fmt.Errorf("LDAP sign-in not implemented yet")}
}
