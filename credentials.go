package fiberauth

import (
	"errors"
	"fmt"
	"strings"

	"github.com/gofiber/fiber/v3"
)

// CheckEmail checks if an email is already in use.
// Returns the user if found, or an error if not found.
//
// Parameters:
//   - email: The email address to check
//
// Returns:
//   - *AuthorizationResponse: Response containing user data
//   - *ErrorFields: Error details if check fails
//
// Example:
//
//	response, err := auth.CheckEmail("user@example.com")
//	if err != nil {
//	    // Handle check error
//	}
func (a *Authorization) CheckEmail(email string) (*AuthorizationResponse, *ErrorFields) {
	username := ""
	if !strings.Contains(email, "@") {
		username = email
	}
	user, err := a.findUser(email, username)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return nil, &ErrorFields{Error: fmt.Errorf("this not found"), Field: "email"}
		}
		return nil, &ErrorFields{Error: err, Field: "email"}
	}
	return &AuthorizationResponse{
		User: userResponse(user),
	}, nil
}

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
func (a *Authorization) SignIn(request *SignInRequest) (*AuthorizationResponse, *ErrorFields) {
	// Validate request
	validator := NewValidator()
	if err := validator.ValidateSignInRequest(request); err != nil {
		return nil, err
	}

	user, err := a.findUser(request.Email, request.Username)
	if err != nil {
		if err == ErrUserNotFound {
			field := "email"
			if request.Username != "" {
				field = "username"
			}
			return nil, &ErrorFields{Error: ErrUserNotFound, Field: field}
		}
		return nil, &ErrorFields{Error: err}
	}

	if user.Password == nil {
		return nil, &ErrorFields{Error: ErrInvalidCredentials, Field: "password"}
	}

	if !a.IsValidPassword(*user.Password, request.Password) {
		return nil, &ErrorFields{Error: ErrInvalidCredentials, Field: "password"}
	}

	tokens, sessionID, err := a.authorize(user, "", "")
	if err != nil {
		return nil, &ErrorFields{Error: err}
	}

	// Create and store session
	sessionManager := NewSessionManager(a)
	if err := sessionManager.CreateAndStoreSession(user, sessionID); err != nil {
		return nil, &ErrorFields{Error: err}
	}

	return sessionManager.CreateAuthorizationResponse(user, tokens, sessionID), nil
}

// SignUp registers a new user with the provided credentials.
// Validates required fields and creates a new user account.
//
// Parameters:
//   - request: SignUpRequest containing user registration data
//
// Returns:
//   - *AuthorizationResponse: Response containing tokens, session ID, and user data
//   - *ErrorFields: Error details if registration fails
//
// Example:
//
//	response, err := auth.SignUp(&SignUpRequest{
//	    FirstName: "John",
//	    LastName:  "Doe",
//	    Email:     "john@example.com",
//	    Password:  "password123",
//	})
//	if err != nil {
//	    // Handle registration error
//	}
func (a *Authorization) SignUp(request *SignUpRequest) (*AuthorizationResponse, *ErrorFields) {
	// Validate required fields
	validator := NewValidator()
	if err := validator.ValidateSignUpRequest(request); err != nil {
		return nil, err
	}

	user, err := a.findUser(request.Email, request.Username)
	if err != nil || user == nil {
		if err == ErrUserNotFound {
			return a.createNewUser(request)
		}
		return nil, &ErrorFields{Error: err}
	}

	// User already exists
	field := "email"
	if request.Username != "" {
		field = "username"
	}
	return nil, &ErrorFields{Error: fmt.Errorf("%s already exists", field), Field: field}
}

// createNewUser creates a new user and returns the authorization response
func (a *Authorization) createNewUser(request *SignUpRequest) (*AuthorizationResponse, *ErrorFields) {
	password := a.CreatePassword(request.Password)
	user := &User{
		FirstName: request.FirstName,
		LastName:  request.LastName,
		Email:     request.Email,
		Password:  &password,
	}

	if request.Username != "" {
		user.Username = &request.Username
	}

	if err := a.sqlStorage.Create(user).Error; err != nil {
		return nil, &ErrorFields{Error: err}
	}

	tokens, sessionID, err := a.authorize(user, "", "")
	if err != nil {
		return nil, &ErrorFields{Error: err}
	}

	// Create and store session
	sessionManager := NewSessionManager(a)
	if err := sessionManager.CreateAndStoreSession(user, sessionID); err != nil {
		return nil, &ErrorFields{Error: err}
	}

	return sessionManager.CreateAuthorizationResponse(user, tokens, sessionID), nil
}

// HandleRefreshToken processes a refresh token from the request context.
// Extracts the token from headers and generates a new access token.
//
// Parameters:
//   - c: Fiber context containing the request
//
// Returns:
//   - string: New access token
//   - error: Error if token refresh fails
//
// Example:
//
//	newToken, err := auth.HandleRefreshToken(c)
//	if err != nil {
//	    // Handle refresh error
//	}
func (a *Authorization) HandleRefreshToken(c fiber.Ctx) (string, error) {
	// Extract and validate token from header
	token, err := a.GetTokenFromHeader(c)
	if err != nil {
		return "", err
	}

	// Extract claims from the refresh token
	claims, err := a.ExtractToken(token)
	if err != nil {
		return "", err
	}

	sessionData, err := a.GetSessionFromDB(claims.SessionID)
	if err != nil {
		return "", err
	}

	// Generate new access token
	newToken, err := a.RefreshAccessToken(&JWTOptions{
		SessionID: claims.SessionID,
		UserID:    claims.UserID,
		Metadata:  sessionData.Metadata,
		Roles:     sessionData.Roles,
	})
	if err != nil {
		return "", err
	}

	return newToken, nil
}

// SignOut invalidates the current user session.
// Removes session data from Redis and invalidates tokens.
//
// Parameters:
//   - request: SignOutRequest containing token information
//
// Returns:
//   - *SignOutResponse: Response indicating successful sign out
//   - *ErrorFields: Error details if sign out fails
//
// Example:
//
//	response, err := auth.SignOut(&SignOutRequest{
//	    Token: "refresh-token-123",
//	})
//	if err != nil {
//	    // Handle sign out error
//	}
func (a *Authorization) SignOut(request *SignOutRequest) (*SignOutResponse, *ErrorFields) {
	res := new(SignOutResponse)
	if request.Token != "" {
		// Extract session ID from token and delete from Redis
		claims, err := a.ExtractToken(request.Token)
		if err == nil && claims.SessionID != "" {
			if err := a.DeleteSessionFromRedis(claims.SessionID); err != nil {
				return nil, &ErrorFields{Error: err}
			}
		}
	}
	res.Message = "Successfully signed out"
	return res, nil
}
