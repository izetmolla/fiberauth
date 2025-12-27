package fiberauth

import (
	"github.com/gofiber/fiber/v3"
)

// AuthService defines the core authentication interface.
// This interface allows for easier testing and alternative implementations.
type AuthService interface {
	// Authentication operations
	SignIn(request *SignInRequest) (*AuthorizationResponse, *ErrorFields)
	SignUp(request *SignUpRequest) (*AuthorizationResponse, *ErrorFields)
	SignOut(request *SignOutRequest) (*SignOutResponse, *ErrorFields)
	RefreshToken(accessToken string) (string, error)

	// Session operations
	GetSession(sessionID string) (*SessionData, error)
	CreateSession(userID string, ip, userAgent string, method ...string) (string, error)
	GetSessionID(c fiber.Ctx) string
	SetSessionCookie(c fiber.Ctx, sessionID string)
	RemoveSessionCookie(c fiber.Ctx)

	// Token operations
	GetTokenFromHeader(c fiber.Ctx) (string, error)
	HandleRefreshToken(c fiber.Ctx) (string, error)

	// Configuration
	GetJWTSecret() string
	GetCookieSessionName() string

	// Middleware
	UseAuth(config *AuthConfig) fiber.Handler
	UseAuthorization() fiber.Handler
	AllowOnly(roles []string) fiber.Handler
	AllowOnlyFromCookie(roles []string) fiber.Handler
}

// Ensure Authorization implements AuthService
var _ AuthService = (*Authorization)(nil)
