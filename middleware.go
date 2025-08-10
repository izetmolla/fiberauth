package fiberauth

import (
	"fmt"

	"github.com/gofiber/fiber/v3"
	"github.com/golang-jwt/jwt/v5"
	jwtware "github.com/izetmolla/fiberauth/jwt"
)

// UseAuth creates and returns an authentication middleware handler
//
// The middleware supports both session-based and JWT-based authentication
// depending on the configuration provided.
//
// Parameters:
//   - config: Configuration struct containing roles, redirect settings, and API mode
//
// Returns:
//   - fiber.Handler: The configured authentication middleware
func (a *Authorization) UseAuth(config *AuthConfig) fiber.Handler {
	// Set default configuration if none provided
	if config == nil {
		config = &AuthConfig{OnlyAPI: true}
	}

	return func(c fiber.Ctx) error {
		// Handle API-only endpoints
		if config.OnlyAPI {
			return a.handleAPIEndpoint(c, config)
		}

		// Handle web endpoints with session-based auth
		return a.handleWebEndpoint(c, config)
	}
}

// handleAPIEndpoint handles authentication for API-only endpoints
func (a *Authorization) handleAPIEndpoint(c fiber.Ctx, config *AuthConfig) error {
	token, _ := a.GetTokenFromHeader(c)
	if config.Reauthorize && token == "" {
		return a.handleWebEndpoint(c, config)
	}

	// If reauthorization is not required and roles are specified, use role-based auth
	if !config.Reauthorize && len(config.Roles) > 0 {
		return a.AllowOnly(config.Roles)(c)
	}

	// Use JWT middleware for API authentication
	return jwtware.New(jwtware.Config{
		SigningKey: jwtware.SigningKey{Key: []byte(a.GetJWTSecret())},
	})(c)
}

// handleWebEndpoint handles authentication for web endpoints with session support
func (a *Authorization) handleWebEndpoint(c fiber.Ctx, config *AuthConfig) error {
	sessionID := a.GetSessionID(c)
	if sessionID == "" {
		return a.handleUnauthenticatedUser(c, config)
	}

	session, err := a.GetSession(sessionID)
	if err != nil {
		return a.respondWithError(c, fiber.StatusUnauthorized, "User not authenticated")
	}

	// Check if this is an API endpoint within web context
	if config.OnlyAPI {
		return a.handleAPIWithinWeb(c, session, sessionID)
	}

	// Verify user has required roles
	if !a.hasRequiredRoleFromJSON(config.Roles, session.Roles) {
		return a.respondWithError(c, fiber.StatusForbidden, "Insufficient permissions")
	}

	return c.Next()
}

// handleUnauthenticatedUser handles unauthenticated user requests
func (a *Authorization) handleUnauthenticatedUser(c fiber.Ctx, config *AuthConfig) error {
	if config.RedirectToSignIn {
		return c.Redirect().Status(fiber.StatusMovedPermanently).To(a.getAuthRedirectURL(c))
	}
	return a.respondWithError(c, fiber.StatusUnauthorized, "User not authenticated")
}

// handleAPIWithinWeb handles API requests within web context
func (a *Authorization) handleAPIWithinWeb(c fiber.Ctx, session *SessionData, sessionID string) error {
	authHeader := c.Get("Authorization")
	if authHeader == "" {
		return a.handleMissingAuthHeader(c, session, sessionID)
	}
	return c.Next()
}

// handleMissingAuthHeader handles requests missing Authorization header
func (a *Authorization) handleMissingAuthHeader(c fiber.Ctx, session *SessionData, sessionID string) error {
	user, err := a.findUserByID(session.UserID)
	if err != nil || user == nil {
		return a.respondWithError(c, fiber.StatusUnauthorized, "User not authenticated")
	}

	// Generate new JWT tokens
	accessToken, refreshToken, err := a.GenerateJWT(&JWTOptions{
		SessionID: sessionID,
		UserID:    user.ID,
		Metadata:  user.Metadata,
		Roles:     user.Roles,
	})
	if err != nil {
		return a.respondWithError(c, fiber.StatusUnauthorized, err.Error())
	}

	// Create and store new session
	sessionManager := NewSessionManager(a)
	if err := sessionManager.CreateAndStoreSession(user, sessionID); err != nil {
		return a.respondWithError(c, fiber.StatusUnauthorized, err.Error())
	}

	// Create authorization response
	authResponse := sessionManager.CreateAuthorizationResponse(user, &Tokens{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, sessionID)

	return c.JSON(fiber.Map{
		"reauthorize": true,
		"user":        authResponse.User,
		"tokens":      authResponse.Tokens,
		"session_id":  authResponse.SessionID,
	})
}

// UseAuthorization creates and returns a JWT-based authorization middleware
//
// This middleware is optimized for API endpoints that require JWT validation.
//
// Returns:
//   - fiber.Handler: JWT authorization middleware
func (a *Authorization) UseAuthorization() fiber.Handler {
	return jwtware.New(jwtware.Config{
		SigningKey: jwtware.SigningKey{Key: []byte(a.GetJWTSecret())},
	})
}

// AllowOnly creates a role-based access control middleware
//
// This middleware validates that the authenticated user has at least one
// of the required roles specified in the JWT token.
//
// Parameters:
//   - roles: Slice of role strings that grant access to the endpoint
//
// Returns:
//   - fiber.Handler: Role-based access control middleware
func (a *Authorization) AllowOnly(roles []string) fiber.Handler {
	return func(c fiber.Ctx) error {
		// Extract user from context (set by JWT middleware)
		user, ok := c.Locals("user").(*jwt.Token)
		if !ok {
			return a.respondWithError(c, fiber.StatusUnauthorized, "User not authenticated")
		}

		// Extract and validate JWT claims
		claims, ok := user.Claims.(jwt.MapClaims)
		if !ok {
			return a.respondWithError(c, fiber.StatusForbidden, "Invalid token claims")
		}

		// Extract roles from JWT claims
		jwtRoles, err := a.extractRolesFromClaims(claims)
		if err != nil {
			return a.respondWithError(c, fiber.StatusForbidden, err.Error())
		}

		// Check if user has required roles
		if !a.hasRequiredRole(roles, jwtRoles) {
			return a.respondWithError(c, fiber.StatusForbidden, "Insufficient permissions")
		}

		return c.Next()
	}
}

// extractRolesFromClaims safely extracts roles from JWT claims
func (a *Authorization) extractRolesFromClaims(claims jwt.MapClaims) ([]string, error) {
	rolesClaim, exists := claims["roles"]
	if !exists {
		return nil, fmt.Errorf("no roles found in token")
	}

	// Handle different possible types for roles claim
	switch v := rolesClaim.(type) {
	case []string:
		return v, nil
	case []interface{}:
		return a.convertInterfaceSliceToStrings(v)
	default:
		return nil, fmt.Errorf("invalid roles format in token")
	}
}

// convertInterfaceSliceToStrings converts []interface{} to []string
func (a *Authorization) convertInterfaceSliceToStrings(roles []interface{}) ([]string, error) {
	result := make([]string, 0, len(roles))
	for _, role := range roles {
		if roleStr, ok := role.(string); ok {
			result = append(result, roleStr)
		} else {
			return nil, fmt.Errorf("invalid role type in token")
		}
	}
	return result, nil
}

// AllowOnlyFromCookie creates a cookie-based role-based access control middleware
//
// This middleware validates user authentication and role requirements
// using session cookies instead of JWT tokens.
//
// Parameters:
//   - roles: Slice of role strings that grant access to the endpoint
//
// Returns:
//   - fiber.Handler: Cookie-based role-based access control middleware
func (a *Authorization) AllowOnlyFromCookie(roles []string) fiber.Handler {
	return func(c fiber.Ctx) error {
		// Extract session cookie
		cookie := c.Cookies(a.cookieSessionName)
		if cookie == "" {
			return a.handleMissingCookie(c)
		}

		// Validate session and extract user data
		sessionData, err := a.GetSessionFromDB(cookie)
		if err != nil {
			return a.respondWithError(c, fiber.StatusUnauthorized, "User not authenticated")
		}

		// Check role requirements
		if !a.hasRequiredRoleFromJSON(roles, sessionData.Roles) {
			return a.respondWithError(c, fiber.StatusForbidden, "Insufficient permissions")
		}

		return c.Next()
	}
}

// handleMissingCookie handles requests with missing session cookies
func (a *Authorization) handleMissingCookie(c fiber.Ctx) error {
	// Allow access to auth pages
	if a.isAuthPage(c.Path()) {
		return c.Next()
	}

	// Redirect to sign-in page
	if a.authRedirectURL != "" {
		return c.Redirect().Status(fiber.StatusMovedPermanently).To(a.getAuthRedirectURL(c))
	}

	return a.respondWithError(c, fiber.StatusUnauthorized, "Authentication required")
}

// isAuthPage checks if the current path is an authentication page
func (a *Authorization) isAuthPage(path string) bool {
	authPaths := []string{"/sign-in", "/sign-up"}
	for _, authPath := range authPaths {
		if path == authPath {
			return true
		}
	}
	return false
}

// respondWithError is a helper function to send consistent error responses
func (a *Authorization) respondWithError(c fiber.Ctx, status int, message string) error {
	return c.Status(status).JSON(fiber.Map{
		"error": message,
	})
}
