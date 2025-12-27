package fiberauth

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/izetmolla/fiberauth/pkg/storage/models"
	"github.com/izetmolla/fiberauth/pkg/storage/redis"
	"github.com/izetmolla/fiberauth/pkg/tokens"
	"github.com/izetmolla/fiberauth/pkg/utils"
)

// SignIn authenticates a user with email/username and password.
//
// Security: Passwords are validated using bcrypt. Failed login attempts return
// generic error messages to prevent user enumeration attacks.
//
// Parameters:
//   - request: Sign-in request containing email/username and password
//
// Returns:
//   - *AuthorizationResponse: Response containing tokens and user data
//   - *ErrorFields: Error details if authentication fails
//
// Example:
//
//	response, err := auth.SignIn(&fiberauth.SignInRequest{
//	    Email:    "user@example.com",
//	    Password: "securePassword123",
//	})
//	if err != nil {
//	    // Handle authentication error
//	}
func (a *Authorization) SignIn(request *SignInRequest) (*AuthorizationResponse, *ErrorFields) {
	// Sanitize inputs
	request.Email = utils.SanitizeEmail(request.Email)
	request.Username = utils.SanitizeUsername(request.Username)

	// Execute before hooks
	for _, hook := range a.hooks.BeforeSignIn {
		if err := hook(request); err != nil {
			return nil, &ErrorFields{Error: err, Field: "email"}
		}
	}

	// Validate request
	if err := a.validator.ValidateSignInEmailOrUsername(request.Email, request.Username); err != nil {
		return nil, &ErrorFields{Error: err, Field: "email"}
	}
	if err := a.validator.ValidatePassword(request.Password); err != nil {
		return nil, &ErrorFields{Error: err, Field: "password"}
	}

	// Find user by email or username
	user, err := a.dbManager.FindUserByEmail(request.Email, request.Username)
	if err != nil {
		// Use generic error to prevent user enumeration
		return nil, &ErrorFields{Error: ErrInvalidCredentials, Field: "email"}
	}

	// Verify password
	if user.Password == nil {
		return nil, &ErrorFields{Error: ErrInvalidCredentials, Field: "password"}
	}

	if !a.passwordManager.IsValidPassword(*user.Password, request.Password) {
		return nil, &ErrorFields{Error: ErrInvalidCredentials, Field: "password"}
	}

	// Generate tokens and session
	method := "credentials"
	if request.Method != "" {
		method = request.Method
	}

	tkns, sessionID, err := a.authorize(user, request.IpAddress, request.UserAgent, method)
	if err != nil {
		return nil, &ErrorFields{Error: err}
	}

	// Create session data and cache
	sessionData := &SessionData{
		ID:       sessionID,
		UserID:   user.ID,
		Roles:    utils.EnsureJSON(user.Roles, []string{}),
		Metadata: utils.EnsureJSON(user.Metadata, map[string]any{}),
		Options:  utils.EnsureJSON(user.Options, map[string]any{}),
	}
	a.setRedisSession(sessionData)

	response := &AuthorizationResponse{
		User:      userResponse(user),
		SessionID: sessionID,
		Tokens:    *tkns,
	}

	// Execute after hooks
	for _, hook := range a.hooks.AfterSignIn {
		if err := hook(user, response); err != nil {
			if a.Debug {
				fmt.Printf("AfterSignIn hook error: %v\n", err)
			}
		}
	}

	return response, nil
}

// SignUp registers a new user with the provided credentials.
//
// Security: Passwords are hashed using bcrypt before storage. All inputs are
// sanitized to prevent injection attacks. Email uniqueness is enforced.
//
// Parameters:
//   - request: Sign-up request containing user information
//
// Returns:
//   - *AuthorizationResponse: Response containing tokens and user data
//   - *ErrorFields: Error details if registration fails
//
// Example:
//
//	response, err := auth.SignUp(&fiberauth.SignUpRequest{
//	    Email:     "newuser@example.com",
//	    Password:  "securePassword123",
//	    FirstName: "John",
//	    LastName:  "Doe",
//	})
//	if err != nil {
//	    // Handle registration error
//	}
func (a *Authorization) SignUp(request *SignUpRequest) (*AuthorizationResponse, *ErrorFields) {
	// Execute before hooks
	for _, hook := range a.hooks.BeforeSignUp {
		if err := hook(request); err != nil {
			return nil, &ErrorFields{Error: err, Field: "email"}
		}
	}

	// Sanitize inputs to prevent injection and formatting issues
	request.Email = utils.SanitizeEmail(request.Email)
	request.Username = utils.SanitizeUsername(request.Username)
	request.FirstName = utils.SanitizeName(request.FirstName)
	request.LastName = utils.SanitizeName(request.LastName)

	// Truncate to reasonable lengths to prevent database issues
	request.FirstName = utils.TruncateString(request.FirstName, 100)
	request.LastName = utils.TruncateString(request.LastName, 100)
	request.Email = utils.TruncateString(request.Email, 255)
	if request.Username != "" {
		request.Username = utils.TruncateString(request.Username, 100)
	}

	// Validate request
	if err := a.validator.ValidateRequired(request.FirstName, "first_name"); err != nil {
		return nil, &ErrorFields{Error: err, Field: "first_name"}
	}
	if err := a.validator.ValidateRequired(request.LastName, "last_name"); err != nil {
		return nil, &ErrorFields{Error: err, Field: "last_name"}
	}
	if err := a.validator.ValidateEmail(request.Email); err != nil {
		return nil, &ErrorFields{Error: err, Field: "email"}
	}
	if err := a.validator.ValidatePassword(request.Password); err != nil {
		return nil, &ErrorFields{Error: err, Field: "password"}
	}

	// Check if user already exists
	existingUser, _ := a.dbManager.FindUserByEmail(request.Email, request.Username)
	if existingUser != nil {
		return nil, &ErrorFields{Error: ErrUserAlreadyExists, Field: "email"}
	}

	// Hash password
	hashedPassword, err := a.passwordManager.HashPassword(request.Password)
	if err != nil {
		return nil, &ErrorFields{Error: err, Field: "password"}
	}

	// Create new user
	user := &models.User{
		Email:     request.Email,
		FirstName: request.FirstName,
		LastName:  request.LastName,
		Password:  &hashedPassword,
		Roles:     json.RawMessage(`[]`),
		Metadata:  json.RawMessage(`{}`),
		Options:   json.RawMessage(`{}`),
	}

	if request.Username != "" {
		user.Username = &request.Username
	}

	// Execute before user create hooks
	for _, hook := range a.hooks.BeforeUserCreate {
		if err := hook(user); err != nil {
			return nil, &ErrorFields{Error: err, Field: "email"}
		}
	}

	if err := a.dbManager.CreateUser(user); err != nil {
		return nil, &ErrorFields{Error: err, Field: "email"}
	}

	// Execute after user create hooks
	for _, hook := range a.hooks.AfterUserCreate {
		if err := hook(user); err != nil {
			if a.Debug {
				fmt.Printf("AfterUserCreate hook error: %v\n", err)
			}
		}
	}

	// Generate tokens and session
	method := "credentials"
	if request.Method != "" {
		method = request.Method
	}

	tkns, sessionID, err := a.authorize(user, request.IpAddress, request.UserAgent, method)
	if err != nil {
		return nil, &ErrorFields{Error: err}
	}

	// Create session data and cache
	sessionData := &SessionData{
		ID:       sessionID,
		UserID:   user.ID,
		Roles:    utils.EnsureJSON(user.Roles, []string{}),
		Metadata: utils.EnsureJSON(user.Metadata, map[string]any{}),
		Options:  utils.EnsureJSON(user.Options, map[string]any{}),
	}
	a.setRedisSession(sessionData)

	response := &AuthorizationResponse{
		User:      userResponse(user),
		SessionID: sessionID,
		Tokens:    *tkns,
	}

	// Execute after hooks
	for _, hook := range a.hooks.AfterSignUp {
		if err := hook(user, response); err != nil {
			if a.Debug {
				fmt.Printf("AfterSignUp hook error: %v\n", err)
			}
		}
	}

	return response, nil
}

// SignOut invalidates the current user session.
//
// Parameters:
//   - request: Sign-out request containing the token
//
// Returns:
//   - *SignOutResponse: Response indicating success
//   - *ErrorFields: Error details if sign-out fails
func (a *Authorization) SignOut(request *SignOutRequest) (*SignOutResponse, *ErrorFields) {
	// Extract token
	token := strings.TrimPrefix(request.Token, "Bearer ")
	token = strings.TrimPrefix(token, "Token ")

	if token == "" {
		return nil, &ErrorFields{Error: fmt.Errorf("token is required")}
	}

	// Extract session ID from token
	claims, err := a.tokenManager.ExtractToken(token)
	if err != nil {
		return nil, &ErrorFields{Error: err}
	}

	// Delete session from Redis if available
	if a.redisManager != nil && claims.SessionID != "" {
		_ = a.redisManager.DeleteSession(claims.SessionID)
	}

	return &SignOutResponse{
		Message: "Sign out successful",
	}, nil
}

// RefreshToken refreshes an access token using a refresh token.
//
// Parameters:
//   - accessToken: The refresh token
//
// Returns:
//   - string: New access token
//   - error: Error if refresh fails
func (a *Authorization) RefreshToken(accessToken string) (string, error) {
	// Extract refresh token claims
	claims, err := a.tokenManager.ExtractToken(accessToken)
	if err != nil {
		return "", err
	}

	// Generate new access token
	newAccessToken, err := a.tokenManager.RefreshAccessToken(&tokens.JWTOptions{
		SessionID: claims.SessionID,
		UserID:    claims.UserID,
		Metadata:  claims.Metadata,
		Roles:     claims.Roles,
	})
	if err != nil {
		return "", err
	}

	return newAccessToken, nil
}

// CheckEmail checks if an email exists in the database.
//
// Parameters:
//   - email: The email to check
//
// Returns:
//   - map[string]any: Response indicating if email exists
//   - error: Error if check fails
func (a *Authorization) CheckEmail(email string) (map[string]any, error) {
	user, _ := a.dbManager.FindUserByEmail(email, "")
	return map[string]any{
		"exists": user != nil,
	}, nil
}

// Helper functions

// authorize creates tokens and session for a user.
func (a *Authorization) authorize(user *models.User, ip, userAgent string, method ...string) (*Tokens, string, error) {
	if len(method) == 0 {
		method = []string{"credentials"}
	}

	// Create session
	sessionID, err := a.CreateSession(user.ID, ip, userAgent, method[0])
	if err != nil {
		return nil, "", err
	}

	// Generate tokens
	accessToken, refreshToken, err := a.tokenManager.GenerateJWT(&tokens.JWTOptions{
		SessionID: sessionID,
		UserID:    user.ID,
		Metadata:  user.Metadata,
		Roles:     user.Roles,
		Method:    method[0],
	})
	if err != nil {
		return nil, "", err
	}

	return &Tokens{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, sessionID, nil
}

// setRedisSession stores session data in Redis cache if Redis is available.
func (a *Authorization) setRedisSession(sessionData *SessionData) {
	if a.redisManager != nil {
		redisSessionData := &redis.SessionData{
			ID:       sessionData.ID,
			UserID:   sessionData.UserID,
			Roles:    sessionData.Roles,
			Metadata: sessionData.Metadata,
			Options:  sessionData.Options,
		}
		if err := a.redisManager.SetSession(redisSessionData); err != nil {
			if a.Debug {
				fmt.Printf("Failed to cache session in Redis: %v\n", err)
			}
		}
	}
}

// userResponse formats user data for API responses.
func userResponse(user *models.User) map[string]any {
	return map[string]any{
		"id":         user.ID,
		"first_name": user.FirstName,
		"last_name":  user.LastName,
		"avatar_url": user.AvatarURL,
		"email":      user.Email,
		"username":   user.Username,
		"roles":      user.Roles,
		"metadata":   user.Metadata,
		"options":    user.Options,
	}
}
