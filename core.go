package fiberauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/izetmolla/fiberauth/social"
	"golang.org/x/crypto/bcrypt"
)

// =============================================================================
// CONFIGURATION AND SETUP
// =============================================================================

// applyConfig applies the provided configuration to the Authorization instance.
// This private function handles the initial setup of the authorization system
// with proper validation and default value assignment.
//
// Parameters:
//   - config: The configuration to apply
func (a *Authorization) applyConfig(config *Config) {
	a.jwtSecret = config.JWTSecret
}

// setDefaults sets default values for optional configuration fields.
// This function ensures that all optional configuration fields have
// sensible default values if not explicitly provided.
func (a *Authorization) setDefaults() {
	if a.accessTokenLifetime == nil {
		a.accessTokenLifetime = &defaultAccessTokenLifetime
	} else {
		defaultAccessTokenLifetime = *a.accessTokenLifetime
	}
	if a.refreshTokenLifetime == nil {
		a.refreshTokenLifetime = &defaultRefreshTokenLifetime
	} else {
		defaultRefreshTokenLifetime = *a.refreshTokenLifetime
	}
	if a.signingMethodHMAC == nil {
		a.signingMethodHMAC = &defaultSigningMethodHMAC
	}
	if a.redisTTL == 0 {
		a.redisTTL = defaultRedisTTL
	}
	if a.redisPrefix == "" {
		a.redisPrefix = defaultRedisPrefix
	}
	if a.cookieSessionName == "" || os.Getenv("COOKIE_SESSION_NAME") == "" {
		a.cookieSessionName = defaultCookieSessionName
	}
	if a.mainDomainName != "" && os.Getenv("AUTH_DOMAIN") == "" {
		a.mainDomainName = defaultMainDomainName
	} else {
		a.mainDomainName = os.Getenv("AUTH_DOMAIN")
	}

	if a.authRedirectURL != "" && os.Getenv("AUTH_REDIRECT_URL") == "" {
		a.authRedirectURL = defaultAuthRedirectURL
	} else {
		a.authRedirectURL = os.Getenv("AUTH_REDIRECT_URL")
	}
	if a.passwordCost == nil {
		a.passwordCost = &defaultPasswordCost
	} else {
		defaultPasswordCost = *a.passwordCost
	}
	if a.passwordMinLength == nil {
		a.passwordMinLength = &defaultPasswordMinLength
	} else {
		defaultPasswordMinLength = *a.passwordMinLength
	}

}

// =============================================================================
// PASSWORD MANAGEMENT
// =============================================================================

// IsValidPassword compares a plain text password with an encrypted password hash.
// Uses bcrypt to safely compare the passwords.
//
// Parameters:
//   - encpw: The encrypted password hash to compare against
//   - pw: The plain text password to verify
//
// Returns:
//   - bool: true if passwords match, false otherwise
//
// Example:
//
//	isValid := auth.IsValidPassword(encryptedPassword, "userPassword123")
//	if isValid {
//	    // Password is correct
//	}
func (a *Authorization) IsValidPassword(encpw, pw string) bool {
	return bcrypt.CompareHashAndPassword([]byte(encpw), []byte(pw)) == nil
}

// CreatePasswordWithError generates a bcrypt hash from a plain text password.
// Uses a cost factor of 12 for security and returns an error if hashing fails.
//
// Parameters:
//   - password: The plain text password to hash
//
// Returns:
//   - string: The bcrypt hash of the password
//   - error: Error if hashing fails
//
// Example:
//
//	hashedPassword, err := auth.CreatePasswordWithError("userPassword123")
//	if err != nil {
//	    // Handle error
//	}
//	// Store hashedPassword in database

func (a *Authorization) CreatePassword(password string) (string, error) {
	cost := *a.passwordCost
	encpw, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", err
	}
	return string(encpw), nil
}

func CreatePassword(password string) (string, error) {
	encpw, err := bcrypt.GenerateFromPassword([]byte(password), defaultPasswordCost)
	if err != nil {
		return "", err
	}
	return string(encpw), nil
}

// =============================================================================
// TOKEN MANAGEMENT
// =============================================================================

// GetTokenFromHeader extracts the JWT token from the Authorization header.
// Supports both "Bearer" and "Token" schemes.
//
// Parameters:
//   - c: Fiber context containing the request headers
//
// Returns:
//   - string: The extracted token
//   - error: Error if token extraction fails
//
// Example:
//
//	token, err := auth.GetTokenFromHeader(c)
//	if err != nil {
//	    // Handle error
//	}
func (a *Authorization) GetTokenFromHeader(c fiber.Ctx) (string, error) {
	authHeader := c.Get("Authorization")
	if authHeader == "" {
		return "", errors.New("authorization header is required")
	}

	// Check for Bearer token
	if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
		return authHeader[7:], nil
	}

	// Check for Token scheme
	if len(authHeader) > 6 && authHeader[:6] == "Token " {
		return authHeader[6:], nil
	}

	// Return as-is if no scheme is specified
	return authHeader, nil
}

// ExtractToken parses and validates a JWT token string.
// Returns the claims from the token if valid.
//
// Parameters:
//   - tokenString: The JWT token string to parse
//
// Returns:
//   - *RefreshTokenClaims: The parsed token claims
//   - error: Error if token parsing fails
//
// Example:
//
//	claims, err := auth.ExtractToken(tokenString)
//	if err != nil {
//	    // Handle error
//	}
func (a *Authorization) ExtractToken(tokenString string) (*RefreshTokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &RefreshTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(a.jwtSecret), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*RefreshTokenClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}

// =============================================================================
// USER MANAGEMENT
// =============================================================================

// findUserByID finds a user by their ID.
// Returns the user if found, or an error if not found.
//
// Parameters:
//   - id: The ID of the user to search for
//
// Returns:
func (a *Authorization) findUserByID(id any) (*User, error) {
	var user User
	err := a.sqlStorage.Model(&User{}).Where("id = ? AND deleted_at IS NULL", id).First(&user).Error
	if err != nil {
		return nil, ErrUserNotFound
	}
	return &user, nil
}

// findUser searches for a user by email or username.
// Returns the user if found, or an error if not found.
//
// Parameters:
//   - email: The email address to search for
//   - username: The username to search for
//
// Returns:
//   - *User: The found user
//   - error: Error if user not found or database error occurs
func (a *Authorization) findUser(email string, username string) (*User, error) {
	var user User
	query := a.sqlStorage.Model(&User{})

	if email != "" {
		query = query.Where("email = ? AND deleted_at IS NULL", email)
	} else if username != "" {
		query = query.Where("username = ? AND deleted_at IS NULL", username)
	} else {
		return nil, errors.New("email or username is required")
	}

	err := query.First(&user).Error
	if err != nil {
		return nil, ErrUserNotFound
	}

	return &user, nil
}

// authorize creates tokens and session for a user.
// This is the core authentication method that generates JWT tokens.
//
// Parameters:
//   - user: The user to authorize
//   - ip: The IP address of the user
//   - userAgent: The user agent string
//
// Returns:
//   - *Tokens: The generated access and refresh tokens
//   - string: The session ID
//   - error: Error if authorization fails
func (a *Authorization) authorize(user *User, ip, userAgent string, method ...string) (*Tokens, string, error) {
	if len(method) == 0 {
		method = []string{"credentials"}
	}
	// Create session
	sessionID, err := a.CreateSession(user.ID, ip, userAgent, method[0])
	if err != nil {
		return nil, "", err
	}

	// Generate tokens
	accessToken, refreshToken, err := a.GenerateJWT(&JWTOptions{
		SessionID: sessionID,
		UserID:    user.ID,
		Metadata:  user.Metadata,
		Roles:     user.Roles,
		Method:    method[0], // credentials, social, etc.
	})
	if err != nil {
		return nil, "", err
	}

	return &Tokens{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, sessionID, nil
}

// findOrCreateUser finds an existing user or creates a new one for social login.
// This method is used for OAuth/social authentication flows.
//
// Parameters:
//   - email: The email address to search for
//   - socialUser: The social user data from the provider
//
// Returns:
//   - *User: The found or created user
//   - error: Error if user creation fails
func (a *Authorization) findOrCreateUser(email string, socialUser *social.User) (*User, error) {
	user, err := a.findUser(email, "")
	if err == nil {
		// User exists, update with social data if needed
		return user, nil
	}

	if err == ErrUserNotFound {
		// User doesn't exist, create new user
		return a.createUser(email, socialUser)
	}

	return nil, err
}

// createUser creates a new user from social authentication data.
// This method is used for OAuth/social authentication flows.
//
// Parameters:
//   - email: The email address for the new user
//   - socialUser: The social user data from the provider
//
// Returns:
//   - *User: The created user
//   - error: Error if user creation fails
func (a *Authorization) createUser(email string, socialUser *social.User) (*User, error) {
	user := &User{
		Email:     email,
		FirstName: socialUser.FirstName,
		LastName:  socialUser.LastName,
		AvatarURL: socialUser.AvatarURL,
		Roles:     json.RawMessage(`[]`),
		Metadata:  json.RawMessage(`{}`),
	}

	// Note: social.User doesn't have a Username field, so we skip it
	// If needed, you can extract username from socialUser.RawData or other fields

	if err := a.sqlStorage.Create(user).Error; err != nil {
		return nil, err
	}

	return user, nil
}

// =============================================================================
// SESSION MANAGEMENT
// =============================================================================

// CreateSession creates a new session for a user.
// This method inserts a new session record into the database.
//
// Parameters:
//   - userID: The user ID for the session
//   - ip: The IP address of the user
//   - userAgent: The user agent string
//
// Returns:
//   - string: The session ID
//   - error: Error if session creation fails
//
// Example:
//
//	sessionID, err := auth.CreateSession("user-123", "192.168.1.1", "Mozilla/5.0...")
//	if err != nil {
//	    // Handle error
//	}
func (a *Authorization) CreateSession(userID string, ip, userAgent string, method ...string) (string, error) {
	if a.sqlStorage == nil {
		return "", fmt.Errorf("database connection not available")
	}
	if len(method) == 0 {
		method = []string{"credentials"}
	}
	sessionID := ""
	refreshTokenLifetime, err := ParseCustomDuration(*a.refreshTokenLifetime, "1y")
	if err != nil {
		return "", fmt.Errorf("failed to parse access token lifetime: %w", err)
	}

	expiresAt := time.Now().Add(refreshTokenLifetime)
	session := &Session{
		ID:        uuid.New().String(),
		UserID:    userID,
		IPAddress: &ip,
		Method:    method[0], // credentials, social, etc.
		UserAgent: &userAgent,
		ExpiresAt: &expiresAt,
	}
	err = a.sqlStorage.Create(session).Error
	if err != nil {
		return "", err
	}
	sessionID = session.ID
	return sessionID, nil
}

// setRedisSession stores session data in Redis cache.
// This is a helper method for caching session information.
//
// Parameters:
//   - session: The session data to store
func (a *Authorization) setRedisSession(session *SessionData) {
	if a.redisStorage != nil {
		if err := a.SetSessionToRedis(session); err != nil {
			// Log error but don't fail the request
			if a.Debug {
				fmt.Printf("Failed to cache session in Redis: %v\n", err)
			}
		}
	}
}

// =============================================================================
// ROLE MANAGEMENT
// =============================================================================

// hasRequiredRole checks if a user has the required roles.
// Compares user roles against required roles.
//
// Parameters:
//   - requiredRoles: The roles required for access
//   - userRoles: The user's roles
//
// Returns:
//   - bool: true if user has required roles, false otherwise
func (a *Authorization) hasRequiredRole(requiredRoles []string, userRoles []string) bool {
	if len(requiredRoles) == 0 {
		return true
	}

	for _, requiredRole := range requiredRoles {
		if slices.Contains(userRoles, requiredRole) {
			return true
		}
	}

	return false
}

// hasRequiredRoleFromJSON checks if a user has the required roles from JSON data.
// Parses JSON roles and compares against required roles.
//
// Parameters:
//   - requiredRoles: The roles required for access
//   - userRoles: The user's roles as JSON
//
// Returns:
//   - bool: true if user has required roles, false otherwise
func (a *Authorization) hasRequiredRoleFromJSON(requiredRoles []string, userRoles json.RawMessage) bool {
	if len(requiredRoles) == 0 {
		return true
	}

	var roles []string
	if err := json.Unmarshal(userRoles, &roles); err != nil {
		return false
	}

	return a.hasRequiredRole(requiredRoles, roles)
}

// =============================================================================
// UTILITY METHODS
// =============================================================================

// getAuthRedirectURL gets the authentication redirect URL from context or configuration.
// This method is used for OAuth redirects.
//
// Parameters:
//   - c: Fiber context containing the request
//
// Returns:
//   - string: The redirect URL
func (a *Authorization) getAuthRedirectURL(c fiber.Ctx) string {
	scheme := "http"
	if c.Protocol() == "https" || c.Secure() {
		scheme = "https"
	}
	fullURL := fmt.Sprintf("%s://%s%s", scheme, c.Hostname(), c.OriginalURL())

	if a.authRedirectURL == "" {
		// No redirect URL configured, return empty to avoid redirect loops
		return ""
	}
	return fmt.Sprintf("%s?redirectUrl=%s", a.authRedirectURL, url.QueryEscape(fullURL))
}

// GetSessionID gets the session ID from the cookie.
// Returns the session ID.
//
// Parameters:
//   - c: Fiber context containing the request
//
// Returns:
//   - string: The session ID
func (a *Authorization) GetSessionID(c fiber.Ctx) string {
	return c.Cookies(a.GetCookieSessionName())
}

// isExcludedPath checks if the current path is excluded from the excluded paths.
// Returns true if the path is excluded, false otherwise.
//
// Parameters:
//   - excluded: The excluded paths
//   - path: The current path
//
// Returns:
//   - bool: true if the path is excluded, false otherwise
func (a *Authorization) isExcludedPath(excluded []string, path string) bool {
	for _, excludedPath := range excluded {
		if strings.HasPrefix(path, excludedPath) {
			return true
		}
	}
	return false
}

func (a *Authorization) getRealIPAddress(c fiber.Ctx) string {
	// Check for Cloudflare's CF-Connecting-IP header first
	if cfIP := c.Get("CF-Connecting-IP"); cfIP != "" {
		return cfIP
	}

	// Check for other common real IP headers
	if realIP := c.Get("X-Real-IP"); realIP != "" {
		return realIP
	}

	if forwardedFor := c.Get("X-Forwarded-For"); forwardedFor != "" {
		// X-Forwarded-For can contain multiple IPs, take the first one
		ips := strings.Split(forwardedFor, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Fallback to the direct connection IP
	return c.IP()
}

func userResponse(user *User) map[string]any {
	return map[string]any{
		"id":         user.ID,
		"first_name": user.FirstName,
		"last_name":  user.LastName,
		"avatar_url": user.AvatarURL,
		"email":      user.Email,
		"username":   user.Username,
		"roles":      user.Roles,
		"metadata":   user.Metadata,
	}
}
