# FiberAuth Module - AI Implementation Context

**Version:** 2.0.0  
**Purpose:** Strict context document for AI tools implementing FiberAuth in other projects  
**Last Updated:** 2025-12-27

---

## 📋 Table of Contents

1. [Module Overview](#module-overview)
2. [Architecture & Structure](#architecture--structure)
3. [Required Dependencies](#required-dependencies)
4. [Initialization & Configuration](#initialization--configuration)
5. [Core API Methods](#core-api-methods)
6. [Middleware Usage](#middleware-usage)
7. [Request/Response Types](#requestresponse-types)
8. [Error Handling](#error-handling)
9. [Security Requirements](#security-requirements)
10. [Common Implementation Patterns](#common-implementation-patterns)
11. [Database Setup](#database-setup)
12. [Testing Patterns](#testing-patterns)
13. [Common Pitfalls](#common-pitfalls)

---

## Module Overview

**FiberAuth** is a modular authentication and authorization system for Go applications using the Fiber v3 framework. It provides:

- JWT token-based authentication
- Session-based authentication
- Role-based access control (RBAC)
- Password hashing with bcrypt
- Optional Redis caching
- Optional OAuth2 social authentication
- Cross-database support (PostgreSQL, MySQL, SQLite, etc.)

**Key Principle:** Import only what you need. The module is designed to prevent unnecessary dependencies.

---

## Architecture & Structure

### Package Organization

```
fiberauth/
├── pkg/
│   ├── config/          # Configuration types (Config, AuthConfig, Request/Response types)
│   ├── credentials/     # Password hashing (bcrypt)
│   ├── errors/          # Error definitions and handling
│   ├── session/         # Session management
│   ├── storage/
│   │   ├── models/      # GORM models (User, Session)
│   │   ├── database/    # Database operations
│   │   └── redis/       # Redis caching (optional)
│   ├── tokens/          # JWT token operations
│   ├── utils/           # Utilities (sanitization, logging, views)
│   ├── validation/     # Input validation
│   └── core/            # Constants
├── auth.go              # Main Authorization struct and New() function
├── auth_credentials.go  # SignIn, SignUp, SignOut methods
├── auth_session.go      # Session management methods
├── auth_social.go       # OAuth social authentication
├── auth_controllers.go  # HTTP controller handlers
├── auth_middleware.go   # Authentication middleware
├── auth_helpers.go      # Helper functions
├── interfaces.go        # AuthService interface
└── security.go          # Security utilities
```

### Core Components

1. **Authorization** struct: Main facade that coordinates all modules
2. **Module Managers**: Specialized managers for database, Redis, tokens, sessions, passwords, validation
3. **Controllers**: HTTP handlers for authentication endpoints
4. **Middleware**: Authentication and authorization middleware

---

## Required Dependencies

### Minimum Required

```go
import (
    "github.com/gofiber/fiber/v3"
    "github.com/izetmolla/fiberauth"
    "gorm.io/gorm"
    "gorm.io/driver/postgres"  // or mysql, sqlite, etc.
)
```

### Optional Dependencies

```go
// For Redis caching
import "github.com/redis/go-redis/v9"

// For social authentication
import "github.com/izetmolla/fiberauth/social/providers/google"
import "github.com/izetmolla/fiberauth/social/providers/github"
// ... other providers
```

---

## Initialization & Configuration

### Basic Initialization (Required)

```go
import (
    "github.com/izetmolla/fiberauth"
    "gorm.io/driver/sqlite"
    "gorm.io/gorm"
)

// 1. Initialize database connection
db, err := gorm.Open(sqlite.Open("auth.db"), &gorm.Config{})
if err != nil {
    log.Fatal(err)
}

// 2. Initialize FiberAuth
auth, err := fiberauth.New(&fiberauth.Config{
    JWTSecret: "your-secret-key-change-in-production", // REQUIRED
    DbClient:  db,                                      // REQUIRED
})
if err != nil {
    log.Fatal(err)
}
```

### Full Configuration Options

```go
auth, err := fiberauth.New(&fiberauth.Config{
    // REQUIRED
    JWTSecret: "your-secret-key",
    DbClient:  db,
    
    // Optional - Redis caching
    RedisClient:    redisClient,
    RedisKeyPrefix: "auth:",
    RedisTTL:       &time.Duration(30 * time.Minute),
    
    // Optional - Token lifetimes (default: "15m" and "7d")
    AccessTokenLifetime:  &"30m",
    RefreshTokenLifetime: &"14d",
    
    // Optional - Password policy (default: cost=12, minLength=8)
    PasswordCost:      &14,
    PasswordMinLength: &10,
    
    // Optional - Cookie settings
    CookieSessionName: &"session",
    MainDomainName:    &"example.com",
    AuthRedirectURL:   &"/login",
    
    // Optional - Custom table names
    UsersModelTable:   "custom_users",
    SessionModelTable: "custom_sessions",
    
    // Optional - Custom API paths
    SignInPath:        "/api/auth/signin",
    SignUpPath:        "/api/auth/signup",
    SignOutPath:       "/api/auth/signout",
    RefreshTokenPath:  "/api/auth/refresh",
    
    // Optional - Social providers
    Providers: []interface{}{
        google.New(clientID, secret, callback, scopes...),
        github.New(clientID, secret, callback, scopes...),
    },
    
    // Optional - Debug mode
    Debug: true,
})
```

### Critical Configuration Rules

1. **JWTSecret MUST be set** - Never use empty or default secrets in production
2. **DbClient MUST be initialized** - Database connection is required
3. **Redis is optional** - Only include if you need session caching
4. **Social providers are optional** - Only include if you need OAuth
5. **Table names default** - Users: "users", Sessions: "sessions", Storage: "storage_items"

---

## Core API Methods

### Authentication Methods

#### SignIn
```go
response, err := auth.SignIn(&fiberauth.SignInRequest{
    Email:    "user@example.com",
    Username: "", // Optional, use email OR username
    Password: "securePassword123",
    // Optional fields:
    IpAddress: "192.168.1.1",
    UserAgent: "Mozilla/5.0...",
    Method:    "credentials",
    Remember:  false,
})

if err != nil {
    // err is *ErrorFields
    // err.Error contains the error
    // err.Field contains the field name if applicable
    return handleError(err)
}

// response is *AuthorizationResponse
// response.User - user data (map[string]any)
// response.Tokens.AccessToken - JWT access token
// response.Tokens.RefreshToken - JWT refresh token
// response.SessionID - session identifier
```

#### SignUp
```go
response, err := auth.SignUp(&fiberauth.SignUpRequest{
    Email:     "newuser@example.com",
    Username:  "newuser", // Optional
    FirstName: "John",
    LastName:  "Doe",
    Password:  "securePassword123",
    // Optional fields:
    IpAddress: "192.168.1.1",
    UserAgent: "Mozilla/5.0...",
    Method:    "credentials",
})

if err != nil {
    // Handle error (same as SignIn)
    return handleError(err)
}
```

#### SignOut
```go
response, err := auth.SignOut(&fiberauth.SignOutRequest{
    Token: "access_token_here", // Optional, can get from header
})

if err != nil {
    return handleError(err)
}
```

### Session Methods

```go
// Get session by ID
session, err := auth.GetSession("session-id-here")
if err != nil {
    // Session not found or expired
}

// Create new session
sessionID, err := auth.CreateSession(
    "user-id",
    "192.168.1.1",
    "Mozilla/5.0...",
    "credentials", // Optional method
)

// Get session ID from cookie
sessionID := auth.GetSessionID(c)

// Set session cookie
auth.SetSessionCookie(c, "session-id")

// Remove session cookie
auth.RemoveSessionCookie(c)
```

### Token Methods

```go
// Get token from Authorization header
token, err := auth.GetTokenFromHeader(c)
if err != nil {
    // No token found
}

// Refresh access token
newAccessToken, err := auth.RefreshToken("old-access-token")
if err != nil {
    // Token invalid or expired
}
```

### Controller Methods (HTTP Handlers)

```go
// Use these as Fiber route handlers
app.Post("/auth/signup", auth.SignUpController)
app.Post("/auth/signin", auth.SignInController)
app.Post("/auth/signout", auth.SignOutController)
app.Post("/auth/refresh", auth.HandleRefreshTokenController)

// Social authentication
app.Get("/auth/provider/:provider", auth.ProviderLogin)
app.Get("/auth/provider/:provider/callback", auth.ProviderCallBack)
app.Get("/auth/provider/:provider/logout", auth.ProviderLogout)
```

---

## Middleware Usage

### Basic Authentication Middleware

```go
// API-only authentication (JWT tokens)
app.Use(auth.UseAuth(&fiberauth.AuthConfig{
    OnlyAPI: true, // Only accept JWT tokens, no session cookies
}))

// Web authentication (sessions + JWT)
app.Use(auth.UseAuth(&fiberauth.AuthConfig{
    OnlyAPI:          false, // Accept both sessions and JWT
    RedirectToSignIn: true,  // Redirect unauthenticated users to login
}))

// Role-based access control
app.Use(auth.UseAuth(&fiberauth.AuthConfig{
    OnlyAPI: true,
    Roles:   []string{"admin", "moderator"}, // Require one of these roles
}))

// Exclude specific paths
app.Use(auth.UseAuth(&fiberauth.AuthConfig{
    OnlyAPI:       true,
    ExcludedPaths: []string{"/health", "/public/*"},
}))
```

### Middleware Configuration Options

```go
type AuthConfig struct {
    ExcludedPaths    []string // Paths to exclude from authentication
    Roles            []string // Required roles (any one of)
    Reauthorize      bool     // Allow reauthorization for API within web
    RedirectToSignIn bool     // Redirect to sign-in page if unauthenticated
    OnlyAPI          bool     // Only accept JWT tokens (no session cookies)
    Debug            bool     // Enable debug logging
}
```

### Middleware Behavior

1. **OnlyAPI: true**
   - Only accepts JWT tokens from `Authorization: Bearer <token>` header
   - Returns 401 JSON response if unauthenticated
   - Does NOT check session cookies

2. **OnlyAPI: false**
   - Checks session cookies first
   - Falls back to JWT tokens if no session
   - Can redirect to login page if `RedirectToSignIn: true`

3. **Roles: []string{"admin"}**
   - User must have at least one of the specified roles
   - Roles are checked from JWT claims or session data
   - Returns 403 if user lacks required roles

4. **ExcludedPaths: []string{"/health"}**
   - These paths bypass authentication
   - Supports wildcards: `[]string{"/public/*"}`

---

## Request/Response Types

### SignInRequest
```go
type SignInRequest struct {
    Email     string `json:"email"`      // Email OR username (one required)
    Username  string `json:"username"`    // Email OR username (one required)
    Password  string `json:"password"`    // Required
    Remember  bool   `json:"remember"`    // Optional
    IpAddress string `json:"ip_address"`  // Optional, auto-detected
    UserAgent string `json:"user_agent"`  // Optional, auto-detected
    Method    string `json:"method"`      // Optional, default: "credentials"
}
```

### SignUpRequest
```go
type SignUpRequest struct {
    Email     string `json:"email"`      // Required
    Username  string `json:"username"`   // Optional
    FirstName string `json:"first_name"` // Required
    LastName  string `json:"last_name"`  // Required
    Password  string `json:"password"`   // Required
    IpAddress string `json:"ip_address"` // Optional
    UserAgent string `json:"user_agent"` // Optional
    Method    string `json:"method"`     // Optional
}
```

### AuthorizationResponse
```go
type AuthorizationResponse struct {
    User      any    `json:"user"`       // User data (map[string]any)
    SessionID string `json:"session_id"` // Session identifier
    Tokens    Tokens `json:"tokens"`      // Access and refresh tokens
}

type Tokens struct {
    AccessToken  string `json:"access_token"`
    RefreshToken string `json:"refresh_token"`
}
```

### ErrorFields
```go
type ErrorFields struct {
    Error error  // The actual error
    Field string // Field name if field-specific error
}
```

### Common Errors (Exported)
```go
var (
    ErrInvalidCredentials = errors.ErrInvalidCredentials
    ErrUserNotFound       = errors.ErrUserNotFound
    ErrUserAlreadyExists  = errors.ErrUserAlreadyExists
    ErrInvalidToken       = errors.ErrInvalidToken
    ErrTokenExpired       = errors.ErrTokenExpired
    ErrUnauthorized       = errors.ErrUnauthorized
)
```

---

## Error Handling

### Standard Error Pattern

```go
response, err := auth.SignIn(&fiberauth.SignInRequest{
    Email:    "user@example.com",
    Password: "password",
})

if err != nil {
    // err is *ErrorFields
    if err.Field != "" {
        // Field-specific error
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": true,
            "field": err.Field,
            "message": err.Error.Error(),
        })
    }
    // General error
    return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
        "error": true,
        "message": err.Error.Error(),
    })
}
```

### Error Response Helper

```go
// Use the built-in error JSON helper
return c.Status(fiber.StatusUnauthorized).JSON(auth.ErrorJSON(err))
// Returns: {"error": true, "message": "error message"}
```

### Common Error Scenarios

1. **Invalid Credentials**: `ErrInvalidCredentials` (prevents user enumeration)
2. **User Not Found**: `ErrUserNotFound`
3. **User Already Exists**: `ErrUserAlreadyExists` (on SignUp)
4. **Invalid Token**: `ErrInvalidToken` (malformed or invalid JWT)
5. **Token Expired**: `ErrTokenExpired`
6. **Unauthorized**: `ErrUnauthorized` (no valid authentication)

---

## Security Requirements

### Critical Security Rules

1. **JWT Secret**
   - MUST be at least 32 characters
   - MUST be cryptographically random
   - MUST be stored securely (environment variables, secrets manager)
   - NEVER commit to version control

2. **Password Requirements**
   - Minimum length enforced (default: 8, configurable)
   - bcrypt hashing with configurable cost (default: 12)
   - Passwords are NEVER stored in plain text
   - Passwords are NEVER logged

3. **Input Sanitization**
   - All inputs are automatically sanitized:
     - Email: trimmed, lowercased
     - Username: alphanumeric + underscore, hyphen, dot only
     - Names: trimmed
   - Length truncation prevents database overflow

4. **Token Security**
   - Access tokens: Short-lived (default: 15 minutes)
   - Refresh tokens: Long-lived (default: 7 days)
   - Tokens signed with HMAC (HS256 by default)
   - Tokens validated on every request

5. **Session Security**
   - Secure cookies (HttpOnly, Secure flags)
   - Session expiration enforced
   - Session data stored in database (and optionally Redis)

6. **Error Messages**
   - Generic error messages prevent user enumeration
   - Field-specific errors only for validation, not authentication

### Security Headers Helper

```go
import "github.com/izetmolla/fiberauth"

// Get recommended security headers
headers := fiberauth.SecureHeaders()
// Returns map with:
// - X-Content-Type-Options: nosniff
// - X-Frame-Options: DENY
// - X-XSS-Protection: 1; mode=block
// - Strict-Transport-Security: max-age=31536000
// - Content-Security-Policy: default-src 'self'
// - Referrer-Policy: strict-origin-when-cross-origin

// Apply to responses
for key, value := range headers {
    c.Set(key, value)
}
```

---

## Common Implementation Patterns

### Pattern 1: Basic API Authentication

```go
package main

import (
    "github.com/gofiber/fiber/v3"
    "github.com/izetmolla/fiberauth"
    "gorm.io/driver/postgres"
    "gorm.io/gorm"
)

func main() {
    // Database
    db, _ := gorm.Open(postgres.Open("..."), &gorm.Config{})
    
    // Auth
    auth, _ := fiberauth.New(&fiberauth.Config{
        JWTSecret: os.Getenv("JWT_SECRET"),
        DbClient:  db,
    })
    
    app := fiber.New()
    
    // Public routes
    app.Post("/auth/signup", auth.SignUpController)
    app.Post("/auth/signin", auth.SignInController)
    
    // Protected routes
    app.Use(auth.UseAuth(&fiberauth.AuthConfig{OnlyAPI: true}))
    app.Get("/profile", func(c fiber.Ctx) error {
        // User is authenticated, get user ID from JWT
        return c.JSON(fiber.Map{"message": "protected"})
    })
    
    app.Listen(":3000")
}
```

### Pattern 2: Web Application with Sessions

```go
app := fiber.New()

// Public routes
app.Post("/auth/signup", auth.SignUpController)
app.Post("/auth/signin", auth.SignInController)

// Protected routes (sessions + JWT)
app.Use(auth.UseAuth(&fiberauth.AuthConfig{
    OnlyAPI:          false,
    RedirectToSignIn: true,
    AuthRedirectURL:  "/login",
}))

app.Get("/dashboard", func(c fiber.Ctx) error {
    // User authenticated via session or JWT
    return c.Render("dashboard", nil)
})
```

### Pattern 3: Role-Based Access Control

```go
// Admin-only routes
adminGroup := app.Group("/admin")
adminGroup.Use(auth.UseAuth(&fiberauth.AuthConfig{
    OnlyAPI: true,
    Roles:   []string{"admin"},
}))
adminGroup.Get("/users", getUsersHandler)

// Moderator or Admin routes
modGroup := app.Group("/mod")
modGroup.Use(auth.UseAuth(&fiberauth.AuthConfig{
    OnlyAPI: true,
    Roles:   []string{"admin", "moderator"},
}))
modGroup.Get("/reports", getReportsHandler)
```

### Pattern 4: Custom Error Handling

```go
func handleAuthError(c fiber.Ctx, err *fiberauth.ErrorFields) error {
    if err == nil {
        return nil
    }
    
    statusCode := fiber.StatusUnauthorized
    if err.Error == fiberauth.ErrUserAlreadyExists {
        statusCode = fiber.StatusConflict
    } else if err.Error == fiberauth.ErrInvalidCredentials {
        statusCode = fiber.StatusUnauthorized
    }
    
    response := fiber.Map{
        "error": true,
        "message": err.Error.Error(),
    }
    
    if err.Field != "" {
        response["field"] = err.Field
    }
    
    return c.Status(statusCode).JSON(response)
}

// Usage
response, err := auth.SignIn(request)
if err != nil {
    return handleAuthError(c, err)
}
```

### Pattern 5: Getting User Data from Context

```go
// After authentication middleware, get user ID
app.Get("/profile", auth.UseAuth(&fiberauth.AuthConfig{OnlyAPI: true}), 
    func(c fiber.Ctx) error {
        // Get session ID from cookie or header
        sessionID := auth.GetSessionID(c)
        
        // Get full session data
        session, err := auth.GetSession(sessionID)
        if err != nil {
            return c.Status(500).JSON(fiber.Map{"error": "session not found"})
        }
        
        // Get user from database
        user, err := auth.dbManager.FindUserByID(session.UserID)
        // ... use user data
        
        return c.JSON(fiber.Map{"user": user})
    })
```

---

## Database Setup

### Automatic Migration

FiberAuth automatically creates tables on initialization:

- `users` table (or custom name from `UsersModelTable`)
- `sessions` table (or custom name from `SessionModelTable`)
- `storage_items` table (or custom name from `StorageTableName`)

### Manual Migration (if needed)

```go
import "github.com/izetmolla/fiberauth/pkg/storage/models"

// Auto-migrate models
db.AutoMigrate(
    &models.User{},
    &models.Session{},
)
```

### User Model Structure

```go
type User struct {
    ID        string          `gorm:"primaryKey" json:"id"`
    Email     string          `gorm:"uniqueIndex" json:"email"`
    Username  *string         `gorm:"uniqueIndex" json:"username"`
    FirstName string          `json:"first_name"`
    LastName  string          `json:"last_name"`
    Password  *string         `json:"-"` // Never returned in JSON
    AvatarURL *string         `json:"avatar_url"`
    Roles     json.RawMessage `gorm:"type:jsonb" json:"roles"`     // JSON array
    Metadata  json.RawMessage `gorm:"type:jsonb" json:"metadata"`  // JSON object
    Options   json.RawMessage `gorm:"type:jsonb" json:"options"`   // JSON object
    CreatedAt time.Time       `json:"created_at"`
    UpdatedAt time.Time       `json:"updated_at"`
}
```

### Session Model Structure

```go
type Session struct {
    ID        string    `gorm:"primaryKey" json:"id"`
    UserID    string    `gorm:"index" json:"user_id"`
    IPAddress string    `json:"ip_address"`
    UserAgent string    `json:"user_agent"`
    Method    string    `json:"method"`
    ExpiresAt time.Time `gorm:"index" json:"expires_at"`
    CreatedAt time.Time `json:"created_at"`
    UpdatedAt time.Time `json:"updated_at"`
}
```

### Database-Specific Notes

**PostgreSQL:**
- Uses `jsonb` type for JSON fields
- Full support for all features

**MySQL/MariaDB:**
- Uses `JSON` type for JSON fields
- Full support for all features

**SQLite:**
- Uses `TEXT` type for JSON fields
- Full support, but not recommended for production

---

## Testing Patterns

### Test Setup

```go
import (
    "testing"
    "github.com/izetmolla/fiberauth"
    "gorm.io/driver/sqlite"
    "gorm.io/gorm"
)

func createTestAuth(t *testing.T) *fiberauth.Authorization {
    db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
    if err != nil {
        t.Fatal(err)
    }
    
    auth, err := fiberauth.New(&fiberauth.Config{
        JWTSecret: "test-secret-key",
        DbClient:  db,
        Debug:     true,
    })
    if err != nil {
        t.Fatal(err)
    }
    
    return auth
}
```

### Test Authentication Flow

```go
func TestSignIn(t *testing.T) {
    auth := createTestAuth(t)
    
    // Sign up first
    signUpResp, err := auth.SignUp(&fiberauth.SignUpRequest{
        Email:     "test@example.com",
        FirstName: "Test",
        LastName:  "User",
        Password:  "password123",
    })
    assert.NoError(t, err)
    assert.NotNil(t, signUpResp)
    
    // Sign in
    signInResp, err := auth.SignIn(&fiberauth.SignInRequest{
        Email:    "test@example.com",
        Password: "password123",
    })
    assert.NoError(t, err)
    assert.NotNil(t, signInResp)
    assert.NotEmpty(t, signInResp.Tokens.AccessToken)
}
```

### Test Middleware

```go
func TestMiddleware(t *testing.T) {
    auth := createTestAuth(t)
    app := fiber.New()
    
    app.Use(auth.UseAuth(&fiberauth.AuthConfig{OnlyAPI: true}))
    app.Get("/protected", func(c fiber.Ctx) error {
        return c.JSON(fiber.Map{"message": "ok"})
    })
    
    // Test without token (should fail)
    req := httptest.NewRequest("GET", "/protected", nil)
    resp, _ := app.Test(req)
    assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
    
    // Test with valid token (should succeed)
    // ... create token and test
}
```

---

## Common Pitfalls

### ❌ WRONG: Missing JWT Secret

```go
// DON'T DO THIS
auth, _ := fiberauth.New(&fiberauth.Config{
    DbClient: db,
    // Missing JWTSecret!
})
```

**✅ CORRECT:**
```go
auth, _ := fiberauth.New(&fiberauth.Config{
    JWTSecret: os.Getenv("JWT_SECRET"), // Required!
    DbClient:  db,
})
```

### ❌ WRONG: Using Empty or Weak Secrets

```go
// DON'T DO THIS
JWTSecret: "secret",
JWTSecret: "123456",
```

**✅ CORRECT:**
```go
JWTSecret: generateSecureSecret(), // 32+ random bytes
JWTSecret: os.Getenv("JWT_SECRET"), // From environment
```

### ❌ WRONG: Not Handling Errors

```go
// DON'T DO THIS
response, err := auth.SignIn(request)
c.JSON(response) // err might not be nil!
```

**✅ CORRECT:**
```go
response, err := auth.SignIn(request)
if err != nil {
    return handleAuthError(c, err)
}
return c.JSON(response)
```

### ❌ WRONG: Exposing Passwords

```go
// DON'T DO THIS
log.Printf("User password: %s", request.Password)
return c.JSON(fiber.Map{"password": user.Password})
```

**✅ CORRECT:**
```go
// Passwords are automatically excluded from JSON responses
// Never log or return passwords
```

### ❌ WRONG: Wrong Middleware Configuration

```go
// DON'T DO THIS - mixing API and web incorrectly
app.Use(auth.UseAuth(&fiberauth.AuthConfig{
    OnlyAPI:          true,  // Only JWT
    RedirectToSignIn: true,  // This won't work with OnlyAPI!
}))
```

**✅ CORRECT:**
```go
// For API-only
app.Use(auth.UseAuth(&fiberauth.AuthConfig{
    OnlyAPI: true,
}))

// For web with redirects
app.Use(auth.UseAuth(&fiberauth.AuthConfig{
    OnlyAPI:          false,
    RedirectToSignIn: true,
}))
```

### ❌ WRONG: Not Setting Up Database

```go
// DON'T DO THIS - database not initialized
var db *gorm.DB // nil!
auth, _ := fiberauth.New(&fiberauth.Config{
    JWTSecret: "secret",
    DbClient:  db, // nil database!
})
```

**✅ CORRECT:**
```go
db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
if err != nil {
    log.Fatal(err)
}
auth, err := fiberauth.New(&fiberauth.Config{
    JWTSecret: "secret",
    DbClient:  db, // Valid database connection
})
```

### ❌ WRONG: Incorrect Error Type Handling

```go
// DON'T DO THIS
response, err := auth.SignIn(request)
if err != nil {
    return c.JSON(err) // err is *ErrorFields, not error!
}
```

**✅ CORRECT:**
```go
response, err := auth.SignIn(request)
if err != nil {
    return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
        "error": true,
        "message": err.Error.Error(), // err.Error is the actual error
        "field": err.Field,
    })
}
```

---

## Quick Reference Checklist

When implementing FiberAuth in a project, ensure:

- [ ] Database connection initialized and passed to `Config.DbClient`
- [ ] JWT secret set (32+ characters, from environment variable)
- [ ] Error handling implemented for all auth methods
- [ ] Middleware configured correctly (OnlyAPI vs web mode)
- [ ] Session cookies set/removed appropriately
- [ ] Security headers applied (optional but recommended)
- [ ] Password requirements meet your security policy
- [ ] Token lifetimes configured appropriately
- [ ] Redis configured if using session caching
- [ ] Social providers configured if using OAuth
- [ ] Custom table names set if needed
- [ ] Excluded paths configured for public endpoints
- [ ] Role-based access control configured if needed
- [ ] Tests written for authentication flows
- [ ] Production secrets stored securely (not in code)

---

## Additional Resources

- **Package Documentation**: See `pkg/README.md` for package-level docs
- **Examples**: See `examples/` directory for complete working examples
- **GUIDE.md**: Complete usage guide with more details
- **CHANGELOG.md**: Version history and migration notes

---

## Version Compatibility

- **Fiber**: v3.x
- **GORM**: v1.x
- **Go**: 1.21+
- **Redis** (optional): go-redis/v9

---

**END OF CONTEXT DOCUMENT**

This document provides strict context for AI tools implementing FiberAuth. Follow these patterns and avoid the common pitfalls to ensure correct implementation.

