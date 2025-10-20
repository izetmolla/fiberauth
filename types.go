package fiberauth

import (
	"encoding/json"
	"time"

	"github.com/izetmolla/fiberauth/social"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

// Config holds the configuration for the Authorization service.
type Config struct {
	IsMultiNode bool `json:"is_multi_node" yaml:"is_multi_node"`
	Debug       bool `json:"debug" yaml:"debug"` // Enable debug mode for logging and diagnostics

	// Core configuration
	AuthURL     string `json:"auth_url" yaml:"auth_url"`     // Authorization server URL
	JWTSecret   string `json:"jwt_secret" yaml:"jwt_secret"` // Secret key for signing JWTs
	RedisClient *redis.Client
	DbClient    *gorm.DB

	// Redis configuration
	RedisKeyPrefix string         `json:"redis_key_prefix" yaml:"redis_key_prefix"` // Optional prefix for Redis keys
	RedisTTL       *time.Duration `json:"redis_ttl" yaml:"redis_ttl"`               // Optional TTL for Redis keys in seconds

	// Token configuration
	AccessTokenLifetime  *string `json:"access_token_lifetime" yaml:"access_token_lifetime"`   // Lifetime for the access token (e.g., "30s", "1h")
	RefreshTokenLifetime *string `json:"refresh_token_lifetime" yaml:"refresh_token_lifetime"` // Lifetime for the refresh token (e.g., "365d")
	SigningMethodHMAC    *string `json:"signing_method_hmac" yaml:"signing_method_hmac"`       // Signing method (e.g., "HS256")

	// Social provider configuration
	GoogleClientID     *string `json:"google_client_id" yaml:"google_client_id"`
	GoogleClientSecret *string `json:"google_client_secret" yaml:"google_client_secret"`
	GoogleRedirectURL  *string `json:"google_redirect_url" yaml:"google_redirect_url"`
	GitHubClientID     *string `json:"github_client_id" yaml:"github_client_id"`
	GitHubClientSecret *string `json:"github_client_secret" yaml:"github_client_secret"`
	GitHubRedirectURL  *string `json:"github_redirect_url" yaml:"github_redirect_url"`

	// Password configuration
	PasswordCost      *int `json:"password_cost" yaml:"password_cost"`
	PasswordMinLength *int `json:"password_min_length" yaml:"password_min_length"`

	// Cookie configuration
	CookieSessionName *string `json:"cookie_session_name" yaml:"cookie_session_name"`
	MainDomainName    *string `json:"main_domain_name" yaml:"main_domain_name"`
	AuthRedirectURL   *string `json:"auth_redirect_url" yaml:"auth_redirect_url"`

	Providers []social.Provider
}

type AuthConfig struct {
	ExcludedPaths    []string `json:"excluded_paths" yaml:"excluded_paths"`
	Roles            []string `json:"roles" yaml:"roles"`
	Reauthorize      bool     `json:"reauthorize" yaml:"reauthorize"`
	RedirectToSignIn bool     `json:"redirect_to_sign_in" yaml:"redirect_to_sign_in"`
	OnlyAPI          bool     `json:"only_api" yaml:"only_api"`
	Debug            bool     `json:"debug" yaml:"debug"`
}

// SessionData represents session information stored in Redis or database.
type SessionData struct {
	ID       string          `json:"id"`
	UserID   string          `json:"user_id"`
	Roles    json.RawMessage `json:"roles"`
	Metadata json.RawMessage `json:"metadata"`
}

// Tokens represents the access and refresh tokens for a user session.
type Tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// SignInRequest represents a user sign-in request.
type SignInRequest struct {
	Email     string `json:"email"`
	Username  string `json:"username"`
	Remember  bool   `json:"remember"`
	Password  string `json:"password"`
	IpAddress string `json:"ip_address"`
	UserAgent string `json:"user_agent"`
}

// SignUpRequest represents a user registration request.
type SignUpRequest struct {
	Email     string `json:"email"`
	Username  string `json:"username"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Password  string `json:"password"`
	IpAddress string `json:"ip_address"`
	UserAgent string `json:"user_agent"`
}

// AuthorizationResponse represents the response after successful authentication.
type AuthorizationResponse struct {
	User      any    `json:"user"`
	SessionID string `json:"session_id"`
	Tokens    Tokens `json:"tokens"`
}

// SignOutRequest represents a user sign-out request.
type SignOutRequest struct {
	Token string `json:"token"`
}

// SignOutResponse represents the response after successful sign-out.
type SignOutResponse struct {
	Message string `json:"message"`
}
