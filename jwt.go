package fiberauth

import (
	"encoding/json"
	"errors"
	"fmt"
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
}

// GenerateJWT generates a JWT and a refresh token for the given user and options.
//
// Params:
//
//	opt *JWTOptions: Options for generating the JWT, including user ID, secret, lifetimes, and signing method.
//
// Returns:
//
//	accessToken string: The signed JWT access token.
//	refreshToken string: The signed JWT refresh token.
//	err error: Error if token generation fails, otherwise nil.
func (a *Authorization) GenerateJWT(opt *JWTOptions) (accessToken, refreshToken string, err error) {
	accessExpDuration, err := ParseCustomDuration(*a.accessTokenLifetime, "30s")
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

	signingMethod := GetSigningMethod(*a.signingMethodHMAC)

	token := jwt.NewWithClaims(signingMethod, claims)
	accessToken, err = token.SignedString([]byte(a.jwtSecret))
	if err != nil {
		return "", "", err
	}

	refreshExpDuration, err := ParseCustomDuration(*a.refreshTokenLifetime, "365d")
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
	refreshToken, err = refreshTokenObj.SignedString([]byte(a.jwtSecret))
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

// GetSigningMethod returns the JWT signing method based on the provided string.
// Defaults to HS256 if the method is unknown or empty.
//
// Parameters:
//   - method: The signing method string (e.g., "HS256", "HS384", "HS512")
//
// Returns:
//   - *jwt.SigningMethodHMAC: The corresponding signing method
//
// Example:
//
//	signingMethod := GetSigningMethod("HS256")
//	// Returns jwt.SigningMethodHS256
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
//
// Example:
//
//	duration, err := ParseCustomDuration("30s", "1m")
//	if err != nil {
//	    // Handle error
//	}
//	// duration will be 30 seconds
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

// RefreshAccessToken generates a new access token using the provided JWT options.
// This function is typically used to refresh expired access tokens.
//
// Parameters:
//   - opt: JWT options containing user ID, metadata, and roles
//
// Returns:
//   - string: The new access token
//   - error: Error if token generation fails
//
// Example:
//
//	newToken, err := auth.RefreshAccessToken(&JWTOptions{
//	    UserID:   "user-123",
//	    Metadata: metadata,
//	    Roles:    roles,
//	})
//	if err != nil {
//	    // Handle error
//	}
func (a *Authorization) RefreshAccessToken(opt *JWTOptions) (string, error) {
	accessExpDuration, err := ParseCustomDuration(*a.accessTokenLifetime, "30s")
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

	token := jwt.NewWithClaims(GetSigningMethod(*a.signingMethodHMAC), claims)
	return token.SignedString([]byte(a.jwtSecret))
}

// FormatRoles converts JSON raw message roles to a string slice.
// Returns an empty slice if parsing fails.
//
// Parameters:
//   - dbRoles: JSON raw message containing role data
//
// Returns:
//   - []string: Array of role strings
//
// Example:
//
//	roles := auth.FormatRoles(json.RawMessage(`["admin", "user"]`))
//	// Returns: []string{"admin", "user"}
func (a *Authorization) FormatRoles(dbRoles json.RawMessage) []string {
	var roles []string
	err := json.Unmarshal(dbRoles, &roles)
	if err != nil {
		return []string{}
	}
	return roles
}

func GetUser(userInterface any) (*Claims, error) {
	if userInterface == nil {
		return nil, errors.New("user not found in context")
	}

	// Type assert to Claims
	claims, ok := userInterface.(*Claims)
	if !ok {
		return nil, errors.New("invalid user claims type")
	}

	return claims, nil
}
