package fiberauth

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/golang-jwt/jwt/v5"
	jwtware "github.com/izetmolla/fiberauth/jwt"
	"github.com/izetmolla/fiberauth/pkg/tokens"
	"github.com/izetmolla/fiberauth/pkg/utils"
)

// UseAuth creates and returns an authentication middleware handler.
//
// Parameters:
//   - config: Configuration struct containing roles, redirect settings, and API mode
//
// Returns:
//   - fiber.Handler: The configured authentication middleware
func (a *Authorization) UseAuth(config *AuthConfig) fiber.Handler {
	var jwtcfg jwtware.Config
	if config.OnlyAPI {
		jwtcfg = jwtware.MakeCfg(jwtware.Config{
			SigningKey: jwtware.SigningKey{Key: []byte(a.GetJWTSecret())},
		})
	}

	return func(c fiber.Ctx) error {
		if isExcludedPath(config.ExcludedPaths, c.Path()) {
			return c.Next()
		}

		// Set default configuration if none provided
		if config == nil {
			config = &AuthConfig{OnlyAPI: true}
		}

		// Handle API-only endpoints
		if config.OnlyAPI {
			return a.handleAPIEndpoint(c, config, &jwtcfg)
		}

		// Handle web endpoints with session-based auth
		return a.handleWebEndpoint(c, config)
	}
}

// UseAuthorization creates and returns a JWT-based authorization middleware.
func (a *Authorization) UseAuthorization() fiber.Handler {
	return jwtware.New(jwtware.Config{
		SigningKey: jwtware.SigningKey{Key: []byte(a.GetJWTSecret())},
	})
}

// AllowOnly creates a role-based access control middleware.
//
// Parameters:
//   - roles: Slice of role strings that grant access to the endpoint
//
// Returns:
//   - fiber.Handler: Role-based access control middleware
func (a *Authorization) AllowOnly(roles []string) fiber.Handler {
	return func(c fiber.Ctx) error {
		user, ok := c.Locals("user").(*jwt.Token)
		if !ok {
			return c.Status(fiber.StatusUnauthorized).JSON(a.ErrorJSON(ErrUnauthorized))
		}

		claims, ok := user.Claims.(jwt.MapClaims)
		if !ok {
			return c.Status(fiber.StatusForbidden).JSON(a.ErrorJSON(fmt.Errorf("invalid token claims")))
		}

		jwtRoles, err := extractRolesFromClaims(claims)
		if err != nil {
			return c.Status(fiber.StatusForbidden).JSON(a.ErrorJSON(err))
		}

		if !hasRequiredRole(roles, jwtRoles) {
			return c.Status(fiber.StatusForbidden).JSON(a.ErrorJSON(fmt.Errorf("insufficient permissions")))
		}

		return c.Next()
	}
}

// AllowOnlyFromCookie creates a cookie-based role-based access control middleware.
//
// Parameters:
//   - roles: Slice of role strings that grant access to the endpoint
//
// Returns:
//   - fiber.Handler: Cookie-based role-based access control middleware
func (a *Authorization) AllowOnlyFromCookie(roles []string) fiber.Handler {
	return func(c fiber.Ctx) error {
		cookie := c.Cookies(a.cookieSessionName)
		if cookie == "" {
			return a.handleMissingCookie(c)
		}

		sessionData, err := a.GetSessionFromDB(cookie)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(a.ErrorJSON(ErrUnauthorized))
		}

		if !hasRequiredRoleFromJSON(roles, sessionData.Roles) {
			return c.Status(fiber.StatusForbidden).JSON(a.ErrorJSON(fmt.Errorf("insufficient permissions")))
		}

		return c.Next()
	}
}

// Middleware helper functions

func (a *Authorization) handleAPIEndpoint(c fiber.Ctx, config *AuthConfig, jwtcfg *jwtware.Config) error {
	token, _ := a.GetTokenFromHeader(c)
	if config.Reauthorize && token == "" && c.Get(ReauthorizeHandlerIdentifier) == "t" {
		return a.handleWebEndpoint(c, config)
	}

	if jwtcfg == nil {
		return c.Status(fiber.StatusUnauthorized).JSON(a.ErrorJSON(fmt.Errorf("JWT configuration is required")))
	}

	jwtClaims, err := jwtcfg.GetTokenClaims(c, token)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(a.ErrorJSON(err))
	}

	if len(config.Roles) > 0 {
		roles, err := extractRolesFromClaims(jwtClaims)
		if err != nil {
			return c.Status(fiber.StatusForbidden).JSON(a.ErrorJSON(fmt.Errorf("insufficient permissions")))
		}

		if !hasRequiredRole(config.Roles, roles) {
			return c.Status(fiber.StatusForbidden).JSON(a.ErrorJSON(fmt.Errorf("insufficient permissions")))
		}
	}

	return c.Next()
}

func (a *Authorization) handleWebEndpoint(c fiber.Ctx, config *AuthConfig) error {
	sessionID := a.GetSessionID(c)
	if sessionID == "" {
		return a.handleUnauthenticatedUser(c, config)
	}

	session, err := a.GetSession(sessionID)
	if err != nil {
		return a.handleUnauthenticatedUser(c, config)
	}

	if config.OnlyAPI {
		return a.handleAPIWithinWeb(c, session, sessionID)
	}

	if !hasRequiredRoleFromJSON(config.Roles, session.Roles) {
		return c.Status(fiber.StatusForbidden).JSON(a.ErrorJSON(fmt.Errorf("insufficient permissions")))
	}

	return c.Next()
}

func (a *Authorization) handleUnauthenticatedUser(c fiber.Ctx, config *AuthConfig) error {
	if config.RedirectToSignIn {
		redirectURL := a.getAuthRedirectURL(c)
		if redirectURL == "" {
			return c.Next()
		}

		currentPath := c.Path()
		if a.authRedirectURL != "" && currentPath == a.authRedirectURL {
			return c.Next()
		}

		if config.OnlyAPI {
			return c.Status(fiber.StatusUnauthorized).JSON(a.ErrorJSON(ErrUnauthorized))
		}
		return c.Redirect().Status(fiber.StatusTemporaryRedirect).To(redirectURL)
	}
	return c.Status(fiber.StatusUnauthorized).JSON(a.ErrorJSON(ErrUnauthorized))
}

func (a *Authorization) handleAPIWithinWeb(c fiber.Ctx, session *SessionData, sessionID string) error {
	authHeader := c.Get("Authorization")
	if authHeader == "" {
		return a.handleMissingAuthHeader(c, session, sessionID)
	}
	return c.Next()
}

func (a *Authorization) handleMissingAuthHeader(c fiber.Ctx, session *SessionData, sessionID string) error {
	user, err := a.dbManager.FindUserByID(session.UserID)
	if err != nil || user == nil {
		return c.Status(fiber.StatusUnauthorized).JSON(a.ErrorJSON(ErrUnauthorized))
	}

	accessToken, refreshToken, err := a.tokenManager.GenerateJWT(&tokens.JWTOptions{
		SessionID: sessionID,
		UserID:    user.ID,
		Metadata:  user.Metadata,
		Roles:     user.Roles,
	})
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(a.ErrorJSON(err))
	}

	sessionData := &SessionData{
		ID:       sessionID,
		UserID:   user.ID,
		Roles:    utils.EnsureJSON(user.Roles, []string{}),
		Metadata: utils.EnsureJSON(user.Metadata, map[string]any{}),
		Options:  utils.EnsureJSON(user.Options, map[string]any{}),
	}
	a.setRedisSession(sessionData)

	return c.JSON(fiber.Map{
		"reauthorize": true,
		"user":        userResponse(user),
		"tokens": Tokens{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
		},
		"session_id": sessionID,
	})
}

func (a *Authorization) handleMissingCookie(c fiber.Ctx) error {
	if a.authRedirectURL != "" {
		redirectURL := a.getAuthRedirectURL(c)
		if redirectURL == "" {
			return c.Next()
		}

		currentPath := c.Path()
		if currentPath == a.authRedirectURL {
			return c.Next()
		}

		return c.Redirect().Status(fiber.StatusTemporaryRedirect).To(redirectURL)
	}

	return c.Status(fiber.StatusUnauthorized).JSON(a.ErrorJSON(fmt.Errorf("authentication required")))
}

func (a *Authorization) getAuthRedirectURL(c fiber.Ctx) string {
	scheme := "http"
	if c.Protocol() == "https" || c.Secure() {
		scheme = "https"
	}
	fullURL := fmt.Sprintf("%s://%s%s", scheme, c.Hostname(), c.OriginalURL())

	if a.authRedirectURL == "" {
		return ""
	}
	return fmt.Sprintf("%s?redirectUrl=%s", a.authRedirectURL, url.QueryEscape(fullURL))
}

// Helper functions for middleware

func isExcludedPath(excluded []string, path string) bool {
	for _, excludedPath := range excluded {
		if strings.HasPrefix(path, excludedPath) {
			return true
		}
	}
	return false
}

func extractRolesFromClaims(claims jwt.MapClaims) ([]string, error) {
	rolesClaim, exists := claims["roles"]
	if !exists {
		return nil, fmt.Errorf("no roles found in token")
	}

	switch v := rolesClaim.(type) {
	case []string:
		return v, nil
	case []interface{}:
		return convertInterfaceSliceToStrings(v)
	default:
		return nil, fmt.Errorf("invalid roles format in token")
	}
}

func convertInterfaceSliceToStrings(roles []interface{}) ([]string, error) {
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

func hasRequiredRole(requiredRoles []string, userRoles []string) bool {
	if len(requiredRoles) == 0 {
		return true
	}

	for _, requiredRole := range requiredRoles {
		for _, userRole := range userRoles {
			if userRole == requiredRole {
				return true
			}
		}
	}

	return false
}

func hasRequiredRoleFromJSON(requiredRoles []string, userRoles json.RawMessage) bool {
	if len(requiredRoles) == 0 {
		return true
	}

	var roles []string
	if err := json.Unmarshal(userRoles, &roles); err != nil {
		return false
	}

	return hasRequiredRole(requiredRoles, roles)
}
