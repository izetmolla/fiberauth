// Package fiberauth provides a modular authentication system for Fiber v3.
// Import only what you need to avoid unnecessary dependencies.
//
// Basic Usage (without Redis/Social):
//
//	import (
//	    "github.com/izetmolla/fiberauth"
//	    "gorm.io/gorm"
//	)
//
//	auth, err := fiberauth.New(&fiberauth.Config{
//	    JWTSecret: "your-secret-key",
//	    DbClient:  db,
//	})
//
// With Redis caching:
//
//	import (
//	    "github.com/izetmolla/fiberauth"
//	    "github.com/redis/go-redis/v9"
//	)
//
//	auth, err := fiberauth.New(&fiberauth.Config{
//	    JWTSecret:   "your-secret-key",
//	    DbClient:    db,
//	    RedisClient: redisClient,
//	})
//
// With Social providers:
//
//	import (
//	    "github.com/izetmolla/fiberauth"
//	    "github.com/izetmolla/fiberauth/social/providers/google"
//	)
//
//	auth, err := fiberauth.New(&fiberauth.Config{
//	    JWTSecret: "your-secret-key",
//	    DbClient:  db,
//	    Providers: []social.Provider{
//	        google.New(...),
//	    },
//	})
package fiberauth

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"
	"github.com/izetmolla/fiberauth/pkg/config"
	"github.com/izetmolla/fiberauth/pkg/core"
	"github.com/izetmolla/fiberauth/pkg/credentials"
	"github.com/izetmolla/fiberauth/pkg/errors"
	"github.com/izetmolla/fiberauth/pkg/session"
	"github.com/izetmolla/fiberauth/pkg/storage/database"
	"github.com/izetmolla/fiberauth/pkg/storage/models"
	"github.com/izetmolla/fiberauth/pkg/storage/redis"
	"github.com/izetmolla/fiberauth/pkg/tokens"
	"github.com/izetmolla/fiberauth/pkg/utils"
	"github.com/izetmolla/fiberauth/pkg/validation"
	"github.com/izetmolla/fiberauth/social"
	redisclient "github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

// Re-export commonly used types for convenience
type (
	Config                = config.Config
	AuthConfig            = config.AuthConfig
	SessionData           = config.SessionData
	Tokens                = config.Tokens
	SignInRequest         = config.SignInRequest
	SignUpRequest         = config.SignUpRequest
	AuthorizationResponse = config.AuthorizationResponse
	SignOutRequest        = config.SignOutRequest
	SignOutResponse       = config.SignOutResponse
	ErrorFields           = errors.ErrorFields
	User                  = models.User
	Session               = models.Session
)

// Re-export common errors
var (
	ErrInvalidCredentials = errors.ErrInvalidCredentials
	ErrUserNotFound       = errors.ErrUserNotFound
	ErrUserAlreadyExists  = errors.ErrUserAlreadyExists
	ErrInvalidToken       = errors.ErrInvalidToken
	ErrTokenExpired       = errors.ErrTokenExpired
	ErrUnauthorized       = errors.ErrUnauthorized
)

// Re-export identifiers
var (
	RefreshTokenHandlerIdentifier = config.RefreshTokenHandlerIdentifier
	ReauthorizeHandlerIdentifier  = config.ReauthorizeHandlerIdentifier
)

// Re-export model table name functions
var (
	SetUsersTableName    = models.SetUsersTableName
	SetSessionsTableName = models.SetSessionsTableName
)

// Authorization is the main authentication manager.
// It coordinates between different modules (database, redis, tokens, etc.)
type Authorization struct {
	Debug bool

	// Module managers
	dbManager       *database.Manager
	redisManager    *redis.Manager
	tokenManager    *tokens.Manager
	sessionManager  *session.Manager
	passwordManager *credentials.PasswordManager
	validator       *validation.Validator

	// Configuration
	jwtSecret            string
	accessTokenLifetime  string
	refreshTokenLifetime string
	signingMethodHMAC    string
	cookieSessionName    string
	mainDomainName       string
	authRedirectURL      string
	passwordCost         int
	passwordMinLength    int

	// Table names
	usersModelTable   string
	sessionModelTable string

	// Social authentication
	social    *social.SocialData
	providers map[string]social.Provider

	// Raw clients (for advanced usage)
	sqlStorage   *gorm.DB
	redisStorage *redisclient.Client

	// Lifecycle hooks for extensibility
	hooks *core.Hooks
}

// New creates and initializes a new Authorization instance with the provided configuration.
//
// Parameters:
//   - cfg: Configuration struct containing JWT secret, database client, Redis client, and optional settings
//
// Returns:
//   - *Authorization: Initialized authorization instance
//   - error: Error if configuration is invalid or initialization fails
func New(cfg *Config) (*Authorization, error) {
	// Validate required configuration
	if cfg == nil {
		return nil, fmt.Errorf("configuration cannot be nil")
	}
	if cfg.JWTSecret == "" {
		return nil, fmt.Errorf("JWT_SECRET cannot be empty")
	}
	if cfg.DbClient == nil {
		return nil, fmt.Errorf("database client is required")
	}

	// Set defaults
	accessTokenLifetime := config.DefaultAccessTokenLifetime
	if cfg.AccessTokenLifetime != nil && *cfg.AccessTokenLifetime != "" {
		accessTokenLifetime = *cfg.AccessTokenLifetime
	}

	refreshTokenLifetime := config.DefaultRefreshTokenLifetime
	if cfg.RefreshTokenLifetime != nil && *cfg.RefreshTokenLifetime != "" {
		refreshTokenLifetime = *cfg.RefreshTokenLifetime
	}

	signingMethodHMAC := config.DefaultSigningMethodHMAC
	if cfg.SigningMethodHMAC != nil && *cfg.SigningMethodHMAC != "" {
		signingMethodHMAC = *cfg.SigningMethodHMAC
	}

	cookieSessionName := config.DefaultCookieSessionName
	if cfg.CookieSessionName != nil && *cfg.CookieSessionName != "" {
		cookieSessionName = *cfg.CookieSessionName
	}

	mainDomainName := config.DefaultMainDomainName
	if cfg.MainDomainName != nil && *cfg.MainDomainName != "" {
		mainDomainName = *cfg.MainDomainName
	}

	authRedirectURL := config.DefaultAuthRedirectURL
	if cfg.AuthRedirectURL != nil && *cfg.AuthRedirectURL != "" {
		authRedirectURL = *cfg.AuthRedirectURL
	}

	passwordCost := config.DefaultPasswordCost
	if cfg.PasswordCost != nil && *cfg.PasswordCost > 0 {
		passwordCost = *cfg.PasswordCost
	}

	passwordMinLength := config.DefaultPasswordMinLength
	if cfg.PasswordMinLength != nil && *cfg.PasswordMinLength > 0 {
		passwordMinLength = *cfg.PasswordMinLength
	}

	usersModelTable := "users"
	if cfg.UsersModelTable != "" {
		usersModelTable = cfg.UsersModelTable
	}

	sessionModelTable := "sessions"
	if cfg.SessionModelTable != "" {
		sessionModelTable = cfg.SessionModelTable
	}

	// Register table names
	models.SetUsersTableName(usersModelTable)
	models.SetSessionsTableName(sessionModelTable)

	// Initialize module managers
	dbMgr := database.NewManager(cfg.DbClient, usersModelTable, sessionModelTable)

	var redisMgr *redis.Manager
	if cfg.RedisClient != nil {
		redisPrefix := config.DefaultRedisPrefix
		if cfg.RedisKeyPrefix != "" {
			redisPrefix = cfg.RedisKeyPrefix
		}

		redisTTL := config.DefaultRedisTTL
		if cfg.RedisTTL != nil && *cfg.RedisTTL > 0 {
			redisTTL = *cfg.RedisTTL
		}

		redisMgr = redis.NewManager(cfg.RedisClient, redisPrefix, redisTTL)
	}

	tokenMgr := tokens.NewManager(cfg.JWTSecret, accessTokenLifetime, refreshTokenLifetime, signingMethodHMAC)
	sessionMgr := session.NewManager(cookieSessionName, mainDomainName)
	passwordMgr := credentials.NewPasswordManager(passwordCost)
	validator := validation.NewValidator()
	validator.MinPasswordLength = passwordMinLength

	// Initialize social authentication if providers are configured
	var socialData *social.SocialData
	var providers map[string]social.Provider

	if len(cfg.Providers) > 0 {
		// Convert []interface{} to []social.Provider
		socialProviders := make([]social.Provider, 0, len(cfg.Providers))
		for _, p := range cfg.Providers {
			if provider, ok := p.(social.Provider); ok {
				socialProviders = append(socialProviders, provider)
			}
		}

		if len(socialProviders) > 0 {
			social.UseProviders(socialProviders...)
			providers = social.GetProviders()

			socialConfig := &social.SocialDataConfig{
				RedisStorage:     cfg.RedisClient,
				SQLStorage:       cfg.DbClient,
				Debug:            cfg.Debug,
				StorageTableName: cfg.StorageTableName,
			}
			socialData = social.New(socialConfig)
		}
	}

	auth := &Authorization{
		Debug:                cfg.Debug,
		dbManager:            dbMgr,
		redisManager:         redisMgr,
		tokenManager:         tokenMgr,
		sessionManager:       sessionMgr,
		passwordManager:      passwordMgr,
		validator:            validator,
		jwtSecret:            cfg.JWTSecret,
		accessTokenLifetime:  accessTokenLifetime,
		refreshTokenLifetime: refreshTokenLifetime,
		signingMethodHMAC:    signingMethodHMAC,
		cookieSessionName:    cookieSessionName,
		mainDomainName:       mainDomainName,
		authRedirectURL:      authRedirectURL,
		passwordCost:         passwordCost,
		passwordMinLength:    passwordMinLength,
		usersModelTable:      usersModelTable,
		sessionModelTable:    sessionModelTable,
		social:               socialData,
		providers:            providers,
		sqlStorage:           cfg.DbClient,
		redisStorage:         cfg.RedisClient,
		hooks:                core.NewHooks(),
	}

	// Run auto-migration
	if err := auth.AutoMigrate(); err != nil {
		return nil, fmt.Errorf("failed to run auto-migration: %w", err)
	}

	return auth, nil
}

// AutoMigrate checks if tables exist and creates them if they don't.
func (a *Authorization) AutoMigrate() error {
	return a.dbManager.AutoMigrate()
}

// GetJWTSecret returns the JWT secret used for signing tokens.
func (a *Authorization) GetJWTSecret() string {
	return a.jwtSecret
}

// GetCookieSessionName returns the name of the cookie session.
func (a *Authorization) GetCookieSessionName() string {
	return a.cookieSessionName
}

// GetSessionID gets the session ID from the cookie.
func (a *Authorization) GetSessionID(c fiber.Ctx) string {
	return a.sessionManager.GetSessionID(c)
}

// SetSessionCookie sets a session cookie in the HTTP response.
func (a *Authorization) SetSessionCookie(c fiber.Ctx, sessionID string) {
	a.sessionManager.SetSessionCookie(c, sessionID)
}

// RemoveSessionCookie removes the session cookie from the HTTP response.
func (a *Authorization) RemoveSessionCookie(c fiber.Ctx) {
	a.sessionManager.RemoveSessionCookie(c)
}

// CreateSession creates a new session for a user.
func (a *Authorization) CreateSession(userID string, ip, userAgent string, method ...string) (string, error) {
	if len(method) == 0 {
		method = []string{"credentials"}
	}

	sessionID := uuid.New().String()
	refreshTokenLifetime, err := tokens.ParseCustomDuration(a.refreshTokenLifetime, "1y")
	if err != nil {
		return "", fmt.Errorf("failed to parse refresh token lifetime: %w", err)
	}

	expiresAt := time.Now().Add(refreshTokenLifetime)
	sess := &models.Session{
		ID:        sessionID,
		UserID:    userID,
		IPAddress: &ip,
		Method:    method[0],
		UserAgent: &userAgent,
		ExpiresAt: &expiresAt,
	}

	err = a.dbManager.CreateSession(sess)
	if err != nil {
		return "", err
	}

	return sessionID, nil
}

// ErrorJSON creates a standardized error response in JSON format.
func (a *Authorization) ErrorJSON(err error, field ...string) fiber.Map {
	message := ""
	if err != nil {
		message = err.Error()
	}
	errJSON := fiber.Map{"error": fiber.Map{"message": message}}
	if len(field) > 0 {
		errJSON["error"].(fiber.Map)["field"] = field[0]
	}
	return errJSON
}

// JSONErrorString creates a JSON error string for error responses.
func (a *Authorization) JSONErrorString(err error) string {
	jsonBytes, err := json.Marshal(a.ErrorJSON(err))
	if err != nil {
		return `{"error":{"message":"internal error"}}`
	}
	return string(jsonBytes)
}

// RenderRedirectHTML renders the redirect HTML template.
func (a *Authorization) RenderRedirectHTML(params map[string]any) string {
	return utils.RenderRedirectHTML(params)
}

// GetProviders returns all available social providers.
func (a *Authorization) GetProviders() map[string]social.Provider {
	return a.providers
}

// GetProvider retrieves a specific social provider by name.
func (a *Authorization) GetProvider(name string) (social.Provider, error) {
	provider, exists := a.providers[name]
	if !exists {
		return nil, fmt.Errorf("provider %s not found", name)
	}
	return provider, nil
}
