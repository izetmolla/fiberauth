package fiberauth

import (
	"fmt"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/izetmolla/fiberauth/social"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

// AuthorizationInterface defines the interface for authorization operations.
// It provides methods for user authentication, token management, and social provider integration.
type AuthorizationInterface interface {
	// SignIn authenticates a user with email/username and password.
	// Returns an AuthorizationResponse with tokens and user data, or an ErrorFields.
	SignIn(request *SignInRequest) (*AuthorizationResponse, *ErrorFields)

	// SignUp registers a new user with the provided credentials.
	// Returns an AuthorizationResponse with tokens and user data, or an ErrorFields.
	SignUp(request *SignUpRequest) (*AuthorizationResponse, *ErrorFields)

	// RefreshToken refreshes an access token using a refresh token.
	// Returns a new access token string, or an error.
	RefreshToken(accessToken string) (string, error)

	// SignOut invalidates the current user session.
	// Returns a SignOutResponse indicating success, or an ErrorFields.
	SignOut(request *SignOutRequest) (*SignOutResponse, *ErrorFields)

	// HandleRefreshToken processes a refresh token from the request context.
	// Returns a new access token string, or an error.
	HandleRefreshToken(c fiber.Ctx) (string, error)

	// ProviderLogin initiates OAuth login with a social provider.
	// Returns the authorization URL for the provider, or an error.
	ProviderLogin(c fiber.Ctx, providerName string) (string, error)

	// ProviderCallBack handles the OAuth callback from a social provider.
	// Returns an AuthorizationResponse with tokens and user data, or an error.
	ProviderCallBack(c fiber.Ctx, providerName string) (*AuthorizationResponse, error)

	// ProviderLoginController handles the HTTP request for provider login.
	// Returns a fiber error for HTTP response handling.
	ProviderLoginController(c fiber.Ctx) error

	// ProviderCallBackController handles the HTTP callback from a social provider.
	// Returns a fiber error for HTTP response handling.
	ProviderCallBackController(c fiber.Ctx) error

	// ProvidersController returns the list of available social providers.
	// Returns a fiber error for HTTP response handling.
	ProvidersController(c fiber.Ctx) error

	// GetProvider retrieves a specific social provider by name.
	// Returns the provider instance, or an error if not found.
	GetProvider(name string) (social.Provider, error)

	// GetProviders returns all available social providers.
	// Returns a map of provider names to provider instances.
	GetProviders() map[string]social.Provider

	// SignInController handles the HTTP request for user sign-in.
	// Returns a fiber error for HTTP response handling.
	SignInController(c fiber.Ctx) error

	// SignUpController handles the HTTP request for user sign-up.
	// Returns a fiber error for HTTP response handling.
	SignUpController(c fiber.Ctx) error

	// SignOutController handles the HTTP request for user sign-out.
	// Returns a fiber error for HTTP response handling.
	SignOutController(c fiber.Ctx) error

	// HandleRefreshTokenController handles the HTTP request for token refresh.
	// Returns a fiber error for HTTP response handling.
	HandleRefreshTokenController(c fiber.Ctx) error

	// GetCookieSessionName returns the name of the cookie session.
	// Returns the name of the cookie session.
	GetCookieSessionName() string

	// GetSessionID gets the session ID from the cookie.
	// Returns the session ID.
	GetSessionID(c fiber.Ctx) string

	// GetSession gets the session from the database.
	// Returns the session.
	GetSession(sessionID string) (*SessionData, error)

	// UseAuth uses the auth middleware.
	// Returns a fiber handler.
	UseAuth(config *AuthConfig) fiber.Handler
}

// Authorization implements the AuthorizationInterface and provides
// authentication and authorization functionality for the application.
type Authorization struct {
	Debug     bool
	jwtSecret string // Secret key for signing JWTs

	sqlStorage   *gorm.DB
	redisStorage *redis.Client

	redisPrefix string
	redisTTL    time.Duration // TTL for Redis keys

	accessTokenLifetime  *string
	refreshTokenLifetime *string
	signingMethodHMAC    *string

	cookieSessionName string
	mainDomainName    string
	authRedirectURL   string

	social    *social.SocialData
	providers map[string]social.Provider
}

// New creates and initializes a new Authorization instance with the provided configuration.
//
// Parameters:
//   - config: Configuration struct containing JWT secret, database client, Redis client, and optional settings
//
// Returns:
//   - *Authorization: Initialized authorization instance
//   - error: Error if configuration is invalid or initialization fails
//
// Example:
//
//	config := &Config{
//	    JWTSecret:   "your-secret-key",
//	    DbClient:    db,
//	    RedisClient: redisClient,
//	}
//	auth, err := New(config)
//	if err != nil {
//	    // Handle error
//	}
func New(config *Config) (*Authorization, error) {
	// Validate required configuration
	if config == nil {
		return nil, fmt.Errorf("JWT_SECRET secret cannot be empty")
	}
	if config.JWTSecret == "" {
		return nil, fmt.Errorf("JWT_SECRET secret cannot be empty")
	}
	auth := &Authorization{
		jwtSecret:    config.JWTSecret,
		redisStorage: config.RedisClient,
		sqlStorage:   config.DbClient,
		Debug:        config.Debug,
	}

	if config.Providers != nil {
		social.UseProviders(config.Providers...)
		auth.providers = social.GetProviders()
	}

	// Set default values for optional fields
	auth.setDefaults()
	auth.social = social.New(&social.SocialDataConfig{RedisStorage: auth.redisStorage, SQLStorage: auth.sqlStorage, Debug: auth.Debug})

	return auth, nil
}

// GetJWTSecret returns the JWT secret used for signing tokens.
func (a *Authorization) GetJWTSecret() string {
	return a.jwtSecret
}

func (a *Authorization) GetCookieSessionName() string {
	return a.cookieSessionName
}
