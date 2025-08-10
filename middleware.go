package fiberauth

import (
	"fmt"

	"github.com/gofiber/fiber/v3"
	"github.com/golang-jwt/jwt/v5"
	jwtware "github.com/izetmolla/fiberauth/jwt"
)

// UseAuth uses the auth middleware.
//
// Parameters:
//   - config: Configuration struct containing roles, redirect to sign in, and only API
//
// Returns:
//   - fiber.Handler: The auth middleware
func (a *Authorization) UseAuth(config *AuthConfig) fiber.Handler {
	if config == nil {
		config = &AuthConfig{OnlyAPI: true}
	}
	fmt.Println("aaaa", config)
	return func(c fiber.Ctx) error {
		if config.OnlyAPI {
			if !config.Reauthorize {
				if len(config.Roles) > 0 {
					return a.AllowOnly(config.Roles)(c)
				}
				// Call the JWT middleware handler directly and return its result
				return jwtware.New(jwtware.Config{
					SigningKey: jwtware.SigningKey{Key: []byte(a.GetJWTSecret())},
				})(c)
			}
		}
		sessionID := a.GetSessionID(c)
		if sessionID == "" {
			if config.RedirectToSignIn {
				return c.Redirect().Status(fiber.StatusMovedPermanently).To(a.getAuthRedirectURL(c))
			}
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "User not authenticated",
			})
		}
		session, err := a.GetSession(sessionID)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "User not authenticated",
			})
		}
		if config.OnlyAPI {
			token := c.Get("Authorization")
			if token == "" {
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
					"error": "Not implemented",
				})
			}
			return c.Next()
		}
		if !a.hasRequiredRoleFromJSON(config.Roles, session.Roles) {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "Insufficient permissions",
			})
		}
		return c.Next()
	}
}

func (a *Authorization) UseAuthorization() fiber.Handler {
	return jwtware.New(jwtware.Config{
		SigningKey: jwtware.SigningKey{Key: []byte(a.GetJWTSecret())},
	})
}

func (a *Authorization) AllowOnly(roles []string) fiber.Handler {
	return func(c fiber.Ctx) error {
		// Get user from context (set by authentication middleware)
		user, ok := c.Locals("user").(*jwt.Token)
		if !ok {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "User not authenticated",
			})
		}

		// Extract claims from JWT token
		claims, ok := user.Claims.(jwt.MapClaims)
		if !ok {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "Invalid token claims",
			})
		}

		// Get roles from claims
		rolesClaim, ok := claims["roles"]
		if !ok {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "No roles found in token",
			})
		}

		// Convert rolesClaim to array of strings
		var jwtRoles []string
		if rolesSlice, ok := rolesClaim.([]any); ok {
			for _, role := range rolesSlice {
				if roleStr, ok := role.(string); ok {
					jwtRoles = append(jwtRoles, roleStr)
				}
			}
		} else {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "Invalid roles format in token",
			})
		}

		// Check if user has any of the required roles
		if !a.hasRequiredRole(roles, jwtRoles) {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "Insufficient permissions",
			})
		}

		return c.Next()
	}
}

func (a *Authorization) AllowOnlyFomCookie(roles []string) fiber.Handler {
	return func(c fiber.Ctx) error {
		cookie := c.Cookies(a.cookieSessionName)
		if cookie == "" {
			if a.authRedirectURL == "" {
				if c.Path() == "/sign-in" || c.Path() == "/sign-up" {
					return c.Next()
				}
			}
			return c.Redirect().Status(fiber.StatusMovedPermanently).To(a.getAuthRedirectURL(c))
		}

		sessionData, err := a.GetSessionFromDB(cookie)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "User not authenticated",
			})
		}

		if !a.hasRequiredRoleFromJSON(roles, sessionData.Roles) {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "Insufficient permissions",
			})
		}

		return c.Next()
	}
}
