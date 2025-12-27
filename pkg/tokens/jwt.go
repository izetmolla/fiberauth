// Package tokens provides JWT token generation and validation.
// This package isolates JWT functionality to prevent importing JWT libraries unnecessarily.
package tokens

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Claims defines the JWT claims for access tokens.
type Claims struct {
	UserID   string          `json:"user_id"`
	Metadata json.RawMessage `json:"metadata"`
	Roles    json.RawMessage `json:"roles"`
	jwt.RegisteredClaims
}

// RefreshTokenClaims defines the JWT claims for refresh tokens.
type RefreshTokenClaims struct {
	SessionID           string          `json:"session_id"` // Optional session ID for refresh tokens
	UserID              string          `json:"user_id"`
	AccessTokenLifetime string          `json:"tokenlife,omitempty"`
	SigningMethodHMAC   string          `json:"signing_method,omitempty"`
	Metadata            json.RawMessage `json:"metadata,omitempty"`
	Roles               json.RawMessage `json:"roles,omitempty"`
	jwt.RegisteredClaims
}

// JWTOptions holds options for generating JWTs.
type JWTOptions struct {
	SessionID string          `json:"session_id"` // Optional session ID to include in the token
	UserID    string          `json:"user_id"`    // User ID to include in the token
	Metadata  json.RawMessage `json:"metadata"`   // Optional metadata to include in the token
	Roles     json.RawMessage `json:"roles"`      // Optional roles to include in the token
	Method    string          `json:"method"`     // Optional method to include in the token
}

// Manager handles JWT token operations.
type Manager struct {
	jwtSecret            string
	accessTokenLifetime  string
	refreshTokenLifetime string
	signingMethodHMAC    string
}

// NewManager creates a new JWT token manager.
//
// Parameters:
//   - jwtSecret: Secret key for signing tokens
//   - accessTokenLifetime: Lifetime for access tokens (e.g., "30s", "1h")
//   - refreshTokenLifetime: Lifetime for refresh tokens (e.g., "365d")
//   - signingMethodHMAC: Signing method (e.g., "HS256", "HS384", "HS512")
//
// Returns:
//   - *Manager: Token manager instance
func NewManager(jwtSecret, accessTokenLifetime, refreshTokenLifetime, signingMethodHMAC string) *Manager {
	if accessTokenLifetime == "" {
		accessTokenLifetime = "30s"
	}
	if refreshTokenLifetime == "" {
		refreshTokenLifetime = "365d"
	}
	if signingMethodHMAC == "" {
		signingMethodHMAC = "HS256"
	}
	
	return &Manager{
		jwtSecret:            jwtSecret,
		accessTokenLifetime:  accessTokenLifetime,
		refreshTokenLifetime: refreshTokenLifetime,
		signingMethodHMAC:    signingMethodHMAC,
	}
}

// GenerateJWT generates a JWT and a refresh token for the given user and options.
//
// Returns:
//   - accessToken string: The signed JWT access token
//   - refreshToken string: The signed JWT refresh token
//   - err error: Error if token generation fails, otherwise nil
func (m *Manager) GenerateJWT(opt *JWTOptions) (accessToken, refreshToken string, err error) {
	accessExpDuration, err := ParseCustomDuration(m.accessTokenLifetime, "30s")
	if err != nil {
		return "", "", fmt.Errorf("failed to parse access token lifetime: %w", err)
	}
	expirationTime := time.Now().Add(accessExpDuration)
	claims := &Claims{
		UserID:   opt.UserID,
		Metadata: opt.Metadata,
		Roles:    opt.Roles,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	signingMethod := GetSigningMethod(m.signingMethodHMAC)

	token := jwt.NewWithClaims(signingMethod, claims)
	accessToken, err = token.SignedString([]byte(m.jwtSecret))
	if err != nil {
		return "", "", err
	}

	refreshExpDuration, err := ParseCustomDuration(m.refreshTokenLifetime, "365d")
	if err != nil {
		return "", "", fmt.Errorf("failed to parse refresh token lifetime: %w", err)
	}
	refreshExp := time.Now().Add(refreshExpDuration)
	refreshClaims := &RefreshTokenClaims{
		SessionID:           opt.SessionID, // Optional session ID for refresh tokens
		UserID:              opt.UserID,
		AccessTokenLifetime: refreshExpDuration.String(),
		SigningMethodHMAC:   signingMethod.Alg(),
		Metadata:            opt.Metadata,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(refreshExp),
		},
	}

	refreshTokenObj := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshToken, err = refreshTokenObj.SignedString([]byte(m.jwtSecret))
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

// RefreshAccessToken generates a new access token using the provided JWT options.
//
// Parameters:
//   - opt: JWT options containing user ID, metadata, and roles
//
// Returns:
//   - string: The new access token
//   - error: Error if token generation fails
func (m *Manager) RefreshAccessToken(opt *JWTOptions) (string, error) {
	accessExpDuration, err := ParseCustomDuration(m.accessTokenLifetime, "30s")
	if err != nil {
		return "", fmt.Errorf("failed to parse access token lifetime: %w", err)
	}
	expirationTime := time.Now().Add(accessExpDuration)
	claims := &Claims{
		UserID:   opt.UserID,
		Metadata: opt.Metadata,
		Roles:    opt.Roles,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	token := jwt.NewWithClaims(GetSigningMethod(m.signingMethodHMAC), claims)
	return token.SignedString([]byte(m.jwtSecret))
}

// ExtractToken parses and validates a JWT token string.
//
// Parameters:
//   - tokenString: The JWT token string to parse
//
// Returns:
//   - *RefreshTokenClaims: The parsed token claims
//   - error: Error if token parsing fails
func (m *Manager) ExtractToken(tokenString string) (*RefreshTokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &RefreshTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(m.jwtSecret), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*RefreshTokenClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}

// GetSigningMethod returns the JWT signing method based on the provided string.
// Defaults to HS256 if the method is unknown or empty.
//
// Parameters:
//   - method: The signing method string (e.g., "HS256", "HS384", "HS512")
//
// Returns:
//   - *jwt.SigningMethodHMAC: The corresponding signing method
func GetSigningMethod(method string) *jwt.SigningMethodHMAC {
	switch strings.ToLower(method) {
	case "hs256":
		return jwt.SigningMethodHS256
	case "hs384":
		return jwt.SigningMethodHS384
	case "hs512":
		return jwt.SigningMethodHS512
	default:
		return jwt.SigningMethodHS256
	}
}

// ParseCustomDuration parses a custom duration string (e.g., "1d", "30s") or returns the default if empty.
//
// Parameters:
//   - input: The duration string to parse (e.g., "30s", "1h", "7d", "1y")
//   - defaultInput: The default duration string if input is empty
//
// Returns:
//   - time.Duration: The parsed duration
//   - error: Error if parsing fails
func ParseCustomDuration(input, defaultInput string) (time.Duration, error) {
	if input == "" {
		input = defaultInput
	}
	unitMultipliers := map[string]time.Duration{
		"s":  time.Second,
		"m":  time.Minute,
		"h":  time.Hour,
		"d":  time.Hour * 24,
		"w":  time.Hour * 24 * 7,
		"mo": time.Hour * 24 * 30,  // approximate month
		"y":  time.Hour * 24 * 365, // approximate year
	}

	var numPart strings.Builder
	var unitPart strings.Builder

	for _, r := range input {
		if r >= '0' && r <= '9' {
			numPart.WriteRune(r)
		} else {
			unitPart.WriteRune(r)
		}
	}

	num, err := strconv.Atoi(numPart.String())
	if err != nil {
		return 0, fmt.Errorf("invalid number: %w", err)
	}

	unit := unitPart.String()
	multiplier, ok := unitMultipliers[unit]
	if !ok {
		return 0, errors.New("invalid time unit: " + unit)
	}

	return time.Duration(num) * multiplier, nil
}

// FormatRoles converts JSON raw message roles to a string slice.
// Returns an empty slice if parsing fails.
//
// Parameters:
//   - dbRoles: JSON raw message containing role data
//
// Returns:
//   - []string: Array of role strings
func FormatRoles(dbRoles json.RawMessage) []string {
	var roles []string
	err := json.Unmarshal(dbRoles, &roles)
	if err != nil {
		return []string{}
	}
	return roles
}

// GetUser extracts the user claims from the provided interface.
//
// Parameters:
//   - userInterface: The interface containing user claims (typically from context)
//
// Returns:
//   - *Claims: Pointer to Claims struct if successful
//   - error: Error if user not found or type assertion fails
func GetUser(userInterface any) (*Claims, error) {
	if userInterface == nil {
		return nil, errors.New("user not found in context")
	}

	// First try direct type assertion to Claims
	if claims, ok := userInterface.(*Claims); ok {
		return claims, nil
	}

	// Try to handle JWT token structure using reflection
	userValue := reflect.ValueOf(userInterface)
	if userValue.Kind() == reflect.Pointer {
		userValue = userValue.Elem()
	}

	if userValue.Kind() == reflect.Struct {
		for i := 0; i < userValue.NumField(); i++ {
			if i == 3 {
				claimObj := userValue.Field(i).Interface()

				// Try different type assertions for the interface
				var claimsBytes []byte
				var err error

				// Try string first
				if str, ok := claimObj.(string); ok {
					claimsBytes = []byte(str)
				} else if bytes, ok := claimObj.([]byte); ok {
					claimsBytes = bytes
				} else if jsonRaw, ok := claimObj.(json.RawMessage); ok {
					claimsBytes = []byte(jsonRaw)
				} else {
					// Try to marshal the interface to JSON first
					claimsBytes, err = json.Marshal(claimObj)
					if err != nil {
						return nil, fmt.Errorf("failed to marshal claims: %w", err)
					}
				}

				claims := &Claims{}
				err = json.Unmarshal(claimsBytes, &claims)
				if err != nil {
					return nil, fmt.Errorf("failed to unmarshal claims: %w", err)
				}
				return claims, nil
			}
		}
	}

	return nil, errors.New("invalid user claims type")
}

// GetLocalUser extracts the user claims from the provided interface with generic type.
//
// Parameters:
//   - userInterface: The interface containing user claims (typically from context)
//
// Returns:
//   - *T: Pointer to generic type T if successful
//   - error: Error if user not found or type assertion fails
func GetLocalUser[T any](userInterface any) (*T, error) {
	if userInterface == nil {
		return nil, errors.New("user not found in context")
	}

	// Type assert to Claims
	claims, ok := userInterface.(*T)
	if !ok {
		return nil, errors.New("invalid user claims type")
	}

	return claims, nil
}

