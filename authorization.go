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

	passwordCost      *int
	passwordMinLength *int

	social    *social.SocialData
	providers map[string]social.Provider

	// Models
	UsersModelTable   string
	SessionModelTable string

	SignInPath           string
	SignUpPath           string
	SignOutPath          string
	RefreshTokenPath     string
	ProviderLoginPath    string
	ProviderCallbackPath string
	ProviderLogoutPath   string
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
		jwtSecret:            config.JWTSecret,
		redisStorage:         config.RedisClient,
		sqlStorage:           config.DbClient,
		Debug:                config.Debug,
		refreshTokenLifetime: config.RefreshTokenLifetime,
		accessTokenLifetime:  config.AccessTokenLifetime,
		passwordCost:         config.PasswordCost,
		passwordMinLength:    config.PasswordMinLength,
		signingMethodHMAC:    config.SigningMethodHMAC,
		redisPrefix:          config.RedisKeyPrefix,
	}

	// Set Redis TTL from config if provided
	if config.RedisTTL != nil {
		auth.redisTTL = *config.RedisTTL
	}
	if config.CookieSessionName != nil {
		auth.cookieSessionName = *config.CookieSessionName
	}
	if config.MainDomainName != nil {
		auth.mainDomainName = *config.MainDomainName
	}
	if config.AuthRedirectURL != nil {
		auth.authRedirectURL = *config.AuthRedirectURL
	}

	if config.Providers != nil {
		social.UseProviders(config.Providers...)
		auth.providers = social.GetProviders()
	}

	// Initialize table names from config or use defaults
	if config.UsersModelTable != "" {
		auth.UsersModelTable = config.UsersModelTable
	} else {
		auth.UsersModelTable = "users"
	}
	if config.SessionModelTable != "" {
		auth.SessionModelTable = config.SessionModelTable
	} else {
		auth.SessionModelTable = "sessions"
	}

	// Register table names in the global registry so TableName() methods can access them
	SetUsersTableName(auth.UsersModelTable)
	SetSessionsTableName(auth.SessionModelTable)

	// Initialize path names from config or use defaults
	if config.SignInPath != "" {
		auth.SignInPath = config.SignInPath
	} else {
		auth.SignInPath = defaultSignInPath
	}
	if config.SignUpPath != "" {
		auth.SignUpPath = config.SignUpPath
	} else {
		auth.SignUpPath = defaultSignUpPath
	}
	if config.SignOutPath != "" {
		auth.SignOutPath = config.SignOutPath
	} else {
		auth.SignOutPath = defaultSignOutPath
	}
	if config.RefreshTokenPath != "" {
		auth.RefreshTokenPath = config.RefreshTokenPath
	} else {
		auth.RefreshTokenPath = defaultRefreshTokenPath
	}
	if config.ProviderLoginPath != "" {
		auth.ProviderLoginPath = config.ProviderLoginPath
	} else {
		auth.ProviderLoginPath = defaultProviderLoginPath
	}
	if config.ProviderCallbackPath != "" {
		auth.ProviderCallbackPath = config.ProviderCallbackPath
	} else {
		auth.ProviderCallbackPath = defaultProviderCallbackPath
	}
	if config.ProviderLogoutPath != "" {
		auth.ProviderLogoutPath = config.ProviderLogoutPath
	} else {
		auth.ProviderLogoutPath = defaultProviderLogoutPath
	}

	// Set default values for optional fields
	auth.setDefaults()

	// Initialize social data with storage table name from config
	socialConfig := &social.SocialDataConfig{
		RedisStorage:     auth.redisStorage,
		SQLStorage:       auth.sqlStorage,
		Debug:            auth.Debug,
		StorageTableName: config.StorageTableName,
	}
	auth.social = social.New(socialConfig)

	// Run auto-migration if database client is provided
	if auth.sqlStorage != nil {
		if err := auth.AutoMigrate(); err != nil {
			return nil, fmt.Errorf("failed to run auto-migration: %w", err)
		}
	}

	return auth, nil
}

// GetJWTSecret returns the JWT secret used for signing tokens.
func (a *Authorization) GetJWTSecret() string {
	return a.jwtSecret
}

// GetCookieSessionName returns the name of the cookie session.
// This is used to identify the session cookie in HTTP requests.
//
// Returns:
//   - string: The cookie session name
func (a *Authorization) GetCookieSessionName() string {
	return a.cookieSessionName
}

// AutoMigrate checks if tables exist and creates them if they don't.
// Uses the table names specified in UsersModelTable and SessionModelTable.
// If table names are not set, defaults to "users" and "sessions".
//
// Returns:
//   - error: Error if migration fails
//
// Example:
//
//	err := auth.AutoMigrate()
//	if err != nil {
//	    // Handle migration error
//	}
func (a *Authorization) AutoMigrate() error {
	if a.sqlStorage == nil {
		return fmt.Errorf("database client is not initialized")
	}

	// Determine table names to use
	usersTableName := a.UsersModelTable
	if usersTableName == "" {
		usersTableName = "users"
	}

	sessionTableName := a.SessionModelTable
	if sessionTableName == "" {
		sessionTableName = "sessions"
	}

	// Check if users table exists by table name
	userTableExists := a.sqlStorage.Migrator().HasTable(usersTableName)
	if !userTableExists {
		// Create users table with custom table name
		// AutoMigrate handles cross-database compatibility automatically
		if err := a.sqlStorage.Table(usersTableName).AutoMigrate(&User{}); err != nil {
			return fmt.Errorf("failed to create users table '%s': %w", usersTableName, err)
		}
	} else {
		// Table exists, but we still need to migrate schema changes
		// AutoMigrate will add missing columns and indexes without dropping data
		if err := a.sqlStorage.Table(usersTableName).AutoMigrate(&User{}); err != nil {
			return fmt.Errorf("failed to migrate users table '%s': %w", usersTableName, err)
		}
	}

	// Check if sessions table exists by table name
	sessionTableExists := a.sqlStorage.Migrator().HasTable(sessionTableName)
	if !sessionTableExists {
		// Create sessions table with custom table name
		// AutoMigrate handles cross-database compatibility automatically
		if err := a.sqlStorage.Table(sessionTableName).AutoMigrate(&Session{}); err != nil {
			return fmt.Errorf("failed to create sessions table '%s': %w", sessionTableName, err)
		}
	} else {
		// Table exists, but we still need to migrate schema changes
		// AutoMigrate will add missing columns and indexes without dropping data
		if err := a.sqlStorage.Table(sessionTableName).AutoMigrate(&Session{}); err != nil {
			return fmt.Errorf("failed to migrate sessions table '%s': %w", sessionTableName, err)
		}
	}

	return nil
}
