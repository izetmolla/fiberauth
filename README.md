# Authorization Service

A comprehensive authentication and authorization service for Go applications using Fiber framework.

## 📑 Table of Contents

- [Features](#-features)
- [Quick Start](#-quick-start)
  - [Basic Usage](#basic-usage)
  - [With Database and Redis](#with-database-and-redis)
  - [With Middleware](#with-middleware)
- [API Endpoints](#-api-endpoints)
- [Token Refresh](#-token-refresh)
- [Configuration](#-configuration)
- [Database Support](#️-database-support)
- [Advanced Configuration](#-advanced-configuration)
- [Security Features](#️-security-features)
- [Examples](#-examples)
- [Migration and Database Management](#-migration-and-database-management)
- [Social Authentication](#-social-authentication)
- [Error Handling](#-error-handling)
- [Configuration Reference](#-configuration-reference)
- [Performance Considerations](#-performance-considerations)
- [Testing](#-testing)
- [Contributing](#-contributing)
- [Changelog](#-changelog)
- [License](#-license)

## ✨ Features

- ✅ **JWT Authentication** - Secure token-based authentication with access and refresh tokens
- ✅ **Password Hashing** - Bcrypt password hashing with configurable cost
- ✅ **Session Management** - Server-side session tracking with Redis and database support
- ✅ **Input Validation** - Comprehensive request validation
- ✅ **Error Handling** - Structured error responses
- ✅ **Role-Based Access** - Role-based authorization with JSON roles/metadata
- ✅ **Cross-Database Support** - Works with MySQL, MariaDB, PostgreSQL, and SQLite
- ✅ **Custom Table Names** - Configure custom table names for users, sessions, and storage
- ✅ **Auto-Migration** - Automatic database table creation and migration
- ✅ **Custom Paths** - Configurable API endpoint paths
- ✅ **Social Authentication** - OAuth2 support for Google, GitHub, Apple, Azure AD, and more
- ✅ **Passkey Support** - WebAuthn/FIDO2 passkey authentication

## 🚀 Quick Start

### Basic Usage

```go
package main

import (
    "log"
    "github.com/gofiber/fiber/v3"
    "github.com/izetmolla/fiberauth"
)

func main() {
    // Initialize Fiber app
    app := fiber.New()

    // Initialize authorization service
    config := &fiberauth.Config{
        JWTSecret: "your-super-secret-jwt-key",
        Debug:     true,
    }

    auth, err := fiberauth.New(config)
    if err != nil {
        log.Fatal("Failed to initialize authorization:", err)
    }

    // Use authorization controllers
    app.Post("/auth/signup", auth.SignUpController)
    app.Post("/auth/signin", auth.SignInController)
    app.Post("/auth/signout", auth.SignOutController)
    app.Post("/auth/refresh", auth.HandleRefreshTokenController)

    // Start server
    log.Fatal(app.Listen(":3000"))
}
```

### With Database and Redis

```go
package main

import (
    "log"
    "github.com/gofiber/fiber/v3"
    "github.com/redis/go-redis/v9"
    "gorm.io/driver/postgres" // or mysql, sqlite
    "gorm.io/gorm"
    "github.com/izetmolla/fiberauth"
)

func main() {
    // Initialize Fiber app
    app := fiber.New()

    // Initialize database (supports PostgreSQL, MySQL, MariaDB, SQLite)
    db, err := gorm.Open(postgres.Open("postgres://user:pass@localhost/db"), &gorm.Config{})
    if err != nil {
        log.Fatal("Failed to connect to database:", err)
    }

    // Initialize Redis client
    redis := redis.NewClient(&redis.Options{
        Addr: "localhost:6379",
    })

    // Initialize authorization service with storage and custom configuration
    config := &fiberauth.Config{
        JWTSecret:   "your-super-secret-jwt-key",
        Debug:       true,
        DbClient:    db,
        RedisClient: redis,
        
        // Custom table names (optional)
        UsersModelTable:    "core_users",      // Custom users table name
        SessionModelTable:  "core_sessions",   // Custom sessions table name
        StorageTableName:   "core_storage",    // Custom storage table name
        
        // Custom API paths (optional)
        SignInPath:       "/api/auth/login",
        SignUpPath:       "/api/auth/register",
        SignOutPath:      "/api/auth/logout",
        RefreshTokenPath: "/api/auth/refresh",
    }

    auth, err := fiberauth.New(config)
    if err != nil {
        log.Fatal("Failed to initialize authorization:", err)
    }

    // Tables are automatically created/migrated on initialization
    // Use authorization controllers with custom paths
    app.Post(auth.SignUpPath, auth.SignUpController)
    app.Post(auth.SignInPath, auth.SignInController)
    app.Post(auth.SignOutPath, auth.SignOutController)
    app.Post(auth.RefreshTokenPath, auth.HandleRefreshTokenController)

    // Start server
    log.Fatal(app.Listen(":3000"))
}
```

### With Middleware

```go
package main

import (
    "log"
    "github.com/gofiber/fiber/v3"
    "github.com/izetmolla/fiberauth"
)

func main() {
    // Initialize Fiber app
    app := fiber.New()

    // Initialize authorization service
    config := &fiberauth.Config{
        JWTSecret: "your-super-secret-jwt-key",
        Debug:     true,
    }

    auth, err := fiberauth.New(config)
    if err != nil {
        log.Fatal("Failed to initialize authorization:", err)
    }

    // Public routes
    app.Get("/health", func(c fiber.Ctx) error {
        return c.JSON(fiber.Map{"status": "ok"})
    })

    // Authentication routes
    authGroup := app.Group("/auth")
    authGroup.Post("/signup", auth.SignUpController)
    authGroup.Post("/signin", auth.SignInController)
    authGroup.Post("/signout", auth.SignOutController)
    authGroup.Post("/refresh", auth.HandleRefreshTokenController)

    // Protected routes
    protected := app.Group("/protected")
    protected.Use(authMiddleware(auth))
    protected.Get("/profile", func(c fiber.Ctx) error {
        return c.JSON(fiber.Map{"message": "Protected route"})
    })

    // Start server
    log.Fatal(app.Listen(":3000"))
}

// Simple JWT middleware
func authMiddleware(auth *fiberauth.Authorization) fiber.Handler {
    return func(c fiber.Ctx) error {
        token, err := auth.GetTokenFromHeader(c)
        if err != nil {
            return c.Status(401).JSON(fiber.Map{
                "error":   true,
                "message": "No valid token provided",
            })
        }

        claims, err := auth.ExtractToken(token)
        if err != nil {
            return c.Status(401).JSON(fiber.Map{
                "error":   true,
                "message": "Invalid or expired token",
            })
        }

        c.Locals("user_id", claims.UserID)
        return c.Next()
    }
}
```

## �� API Endpoints

### Authentication Endpoints

| Method | Endpoint | Description | Request Body |
|--------|----------|-------------|--------------|
| `POST` | `/auth/signup` | Register a new user | `SignUpRequest` |
| `POST` | `/auth/signin` | Authenticate user | `SignInRequest` |
| `POST` | `/auth/signout` | Logout user | `SignOutRequest` |
| `POST` | `/auth/refresh` | Refresh access token | - |

### Request/Response Examples

#### User Registration

```bash
curl -X POST http://localhost:3000/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "first_name": "John",
    "last_name": "Doe",
    "email": "john@example.com",
    "password": "securepassword123"
  }'
```

**Response**:
```json
{
  "success": true,
  "message": "User created successfully",
  "data": {
    "user": {
      "id": "user-123",
      "first_name": "John",
      "last_name": "Doe",
      "email": "john@example.com"
    },
    "session_id": "session-456",
    "tokens": {
      "access_token": "eyJhbGciOiJIUzI1NiIs...",
      "refresh_token": "eyJhbGciOiJIUzI1NiIs..."
    }
  }
}
```

#### User Authentication

```bash
curl -X POST http://localhost:3000/auth/signin \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "password": "securepassword123"
  }'
```

**Response**:
```json
{
  "success": true,
  "message": "User authenticated successfully",
  "data": {
    "user": {
      "id": "user-123",
      "first_name": "John",
      "last_name": "Doe",
      "email": "john@example.com"
    },
    "session_id": "session-456",
    "tokens": {
      "access_token": "eyJhbGciOiJIUzI1NiIs...",
      "refresh_token": "eyJhbGciOiJIUzI1NiIs..."
    }
  }
}
```

## 🔄 Token Refresh

### Refresh Token Controller

The `HandleRefreshTokenController` provides a way to refresh access tokens without requiring a session. This is particularly useful for API-only applications or stateless authentication flows.

#### How it works:

1. **Token Extraction**: Extracts the refresh token from the `Authorization` header
2. **Token Validation**: Validates the refresh token and extracts session information
3. **Session Verification**: Verifies the session exists in the database/Redis
4. **New Token Generation**: Generates a new access token with updated expiration
5. **Response**: Returns the new access token as a JSON string

#### Usage:

```go
// Add refresh token middleware to API routes
api.Use(auth.HandleRefreshTokenController)

// Or use it as a standalone endpoint
app.Post("/auth/refresh", auth.HandleRefreshTokenController)
```

#### Request Format:

The refresh token should be sent in the `Authorization` header:

```bash
# Using Bearer token format
Authorization: Bearer <refresh_token>

# Using Token format  
Authorization: Token <refresh_token>

# Or just the token itself
Authorization: <refresh_token>
```

#### Response Format:

**Success Response** (200 OK):
```json
"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiMTIzIiwic2Vzc2lvbl9pZCI6InNlc3Npb24tNDU2IiwiZXhwIjoxNzM0NTY3ODkwfQ.example_signature"
```

**Error Response** (401 Unauthorized):
```json
{
  "error": true,
  "message": "Invalid or expired refresh token"
}
```

#### Example Implementation:

```go
package main

import (
    "log"
    "github.com/gofiber/fiber/v3"
    "github.com/izetmolla/fiberauth"
)

func main() {
    app := fiber.New()
    
    // Initialize auth service
    config := &fiberauth.Config{
        JWTSecret: "your-super-secret-jwt-key",
        Debug:     true,
    }
    
    auth, err := fiberauth.New(config)
    if err != nil {
        log.Fatal("Failed to initialize authorization:", err)
    }
    
    // API routes group
    api := app.Group("/api")
    
    // Add refresh token middleware to all API routes
    api.Use(auth.HandleRefreshTokenController)
    
    // Protected API endpoints
    api.Get("/profile", func(c fiber.Ctx) error {
        return c.JSON(fiber.Map{
            "message": "Profile data",
            "user_id": c.Locals("user_id"),
        })
    })
    
    api.Get("/dashboard", func(c fiber.Ctx) error {
        return c.JSON(fiber.Map{
            "message": "Dashboard data",
        })
    })
    
    // Standalone refresh endpoint
    app.Post("/auth/refresh", auth.HandleRefreshTokenController)
    
    log.Fatal(app.Listen(":3000"))
}
```

#### Client-side Usage Example:

```javascript
// JavaScript example
async function refreshToken() {
    try {
        const response = await fetch('/auth/refresh', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${localStorage.getItem('refreshToken')}`,
                'Content-Type': 'application/json'
            }
        });
        
        if (response.ok) {
            const newAccessToken = await response.text();
            localStorage.setItem('accessToken', newAccessToken);
            console.log('Token refreshed successfully');
        } else {
            console.error('Token refresh failed');
            // Redirect to login
        }
    } catch (error) {
        console.error('Error refreshing token:', error);
    }
}

// cURL example
curl -X POST http://localhost:3000/auth/refresh \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -H "Content-Type: application/json"
```

#### Configuration Options:

The refresh token controller uses the `RefreshTokenHandlerIdentifier` header to determine if it should process the request. Set this header to `"yes"` to enable refresh token processing:

```go
// Enable refresh token processing
c.Set("cft", "yes")
```

#### Security Considerations:

- Refresh tokens should have longer expiration times than access tokens
- Store refresh tokens securely on the client side
- Implement token rotation for enhanced security
- Use HTTPS in production to prevent token interception
- Consider implementing refresh token blacklisting for logout scenarios

## 🔧 Configuration

### Environment Variables

```bash
# Required
export JWT_SECRET="your-super-secret-jwt-key"

# Optional
export DEBUG=true
export POSTGRES_URL="postgres://user:pass@localhost/db"
export REDIS_URL="redis://localhost:6379"
```

### Config Structure

```go
type Config struct {
    // Core configuration
    JWTSecret   string          // JWT signing secret (required)
    Debug       bool            // Enable debug mode
    DbClient    *gorm.DB        // Database client (optional)
    RedisClient *redis.Client   // Redis client (optional)
    
    // Token configuration
    AccessTokenLifetime  *string // Lifetime for access token (e.g., "30s", "1h")
    RefreshTokenLifetime *string // Lifetime for refresh token (e.g., "365d")
    SigningMethodHMAC    *string // JWT signing method (e.g., "HS256")
    
    // Redis configuration
    RedisKeyPrefix string         // Prefix for Redis keys (default: "AUTHSESSIONS")
    RedisTTL       *time.Duration // TTL for Redis keys
    
    // Password configuration
    PasswordCost      *int // Bcrypt cost factor (default: 12)
    PasswordMinLength *int // Minimum password length (default: 3)
    
    // Cookie configuration
    CookieSessionName *string // Session cookie name (default: "cnf.id")
    MainDomainName    *string // Domain for cookies (default: "localhost")
    AuthRedirectURL  *string // Redirect URL after auth
    
    // Table name configuration
    UsersModelTable    string // Custom table name for users (default: "users")
    SessionModelTable  string // Custom table name for sessions (default: "sessions")
    StorageTableName   string // Custom table name for storage items (default: "storage_items")
    
    // Path configuration
    SignInPath           string // Path for sign-in endpoint (default: "/auth/signin")
    SignUpPath           string // Path for sign-up endpoint (default: "/auth/signup")
    SignOutPath          string // Path for sign-out endpoint (default: "/auth/signout")
    RefreshTokenPath     string // Path for refresh token endpoint (default: "/auth/refresh")
    ProviderLoginPath    string // Path for provider login (default: "/auth/provider/:provider")
    ProviderCallbackPath string // Path for provider callback (default: "/auth/provider/:provider/callback")
    ProviderLogoutPath   string // Path for provider logout (default: "/auth/provider/:provider/logout")
    
    // Social provider configuration
    Providers []social.Provider // Social authentication providers
}
```

## 🗄️ Database Support

### Supported Databases

The service supports multiple database systems with automatic compatibility handling:

- **PostgreSQL** - Full support with native UUID and JSONB types
- **MySQL** - Full support with VARCHAR and JSON types
- **MariaDB** - Full support (uses MySQL driver)
- **SQLite** - Full support with BLOB and TEXT types

### Cross-Database Compatibility

All models are designed to work seamlessly across all supported databases:

- **UUID Generation**: Uses Go's `uuid` package instead of database-specific functions
- **JSON Fields**: Uses `text` type that works across all databases
- **Auto-Migration**: Automatically creates tables with correct types for each database
- **Table Names**: Configurable table names work consistently across all databases

### Example: SQLite Setup

```go
import (
    "gorm.io/driver/sqlite"
    "gorm.io/gorm"
)

// SQLite database
db, err := gorm.Open(sqlite.Open("auth.db"), &gorm.Config{})
if err != nil {
    log.Fatal(err)
}

config := &fiberauth.Config{
    JWTSecret: "your-secret-key",
    DbClient:  db,
    // Custom table names work with SQLite too
    UsersModelTable:   "app_users",
    SessionModelTable: "app_sessions",
}

auth, err := fiberauth.New(config)
// Tables are automatically created with SQLite-compatible types
```

### Example: MySQL Setup

```go
import (
    "gorm.io/driver/mysql"
    "gorm.io/gorm"
)

// MySQL database
dsn := "user:password@tcp(localhost:3306)/dbname?charset=utf8mb4&parseTime=True&loc=Local"
db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
if err != nil {
    log.Fatal(err)
}

config := &fiberauth.Config{
    JWTSecret: "your-secret-key",
    DbClient:  db,
}

auth, err := fiberauth.New(config)
```

## 🔧 Advanced Configuration

### Custom Table Names

Configure custom table names for your database schema:

```go
config := &fiberauth.Config{
    JWTSecret: "your-secret-key",
    DbClient:  db,
    
    // Custom table names
    UsersModelTable:    "myapp_users",      // Default: "users"
    SessionModelTable:  "myapp_sessions",   // Default: "sessions"
    StorageTableName:   "myapp_storage",    // Default: "storage_items"
}

auth, err := fiberauth.New(config)
// Tables will be created with your custom names
```

### Custom API Paths

Configure custom API endpoint paths:

```go
config := &fiberauth.Config{
    JWTSecret: "your-secret-key",
    
    // Custom API paths
    SignInPath:           "/api/v1/auth/login",
    SignUpPath:           "/api/v1/auth/register",
    SignOutPath:          "/api/v1/auth/logout",
    RefreshTokenPath:     "/api/v1/auth/refresh",
    ProviderLoginPath:    "/api/v1/auth/:provider/login",
    ProviderCallbackPath: "/api/v1/auth/:provider/callback",
    ProviderLogoutPath:   "/api/v1/auth/:provider/logout",
}

auth, err := fiberauth.New(config)

// Use configured paths
app.Post(auth.SignUpPath, auth.SignUpController)
app.Post(auth.SignInPath, auth.SignInController)
```

### Auto-Migration

Tables are automatically created and migrated when you initialize the Authorization service:

```go
config := &fiberauth.Config{
    JWTSecret: "your-secret-key",
    DbClient:  db,
    UsersModelTable:   "custom_users",
    SessionModelTable: "custom_sessions",
}

auth, err := fiberauth.New(config)
// Tables are automatically created if they don't exist
// Schema changes are automatically migrated
```

You can also manually trigger migration:

```go
err := auth.AutoMigrate()
if err != nil {
    log.Fatal("Migration failed:", err)
}
```

## 🛡️ Security Features

- ✅ **JWT Authentication** - Secure token-based authentication with configurable lifetimes
- ✅ **Password Hashing** - Bcrypt password hashing with configurable cost
- ✅ **Session Management** - Server-side session tracking with Redis and database support
- ✅ **Input Validation** - Comprehensive request validation
- ✅ **Error Handling** - Structured error responses
- ✅ **Role-Based Access** - Role-based authorization with JSON roles/metadata
- ✅ **Cross-Database Security** - Secure across all supported database systems

## 📚 Examples

For more detailed examples, see the [examples](./examples/) folder:

- [Basic Authentication](./examples/basic-auth/) - Complete authentication workflow
- [Middleware Usage](./examples/middleware/) - JWT and role-based middleware
- [Error Handling](./examples/error-handling/) - Comprehensive error handling

## 🔄 Migration and Database Management

### Automatic Migration

The service automatically handles database migrations:

- **Table Creation**: Creates tables if they don't exist
- **Schema Updates**: Adds missing columns and indexes
- **Cross-Database**: Works with PostgreSQL, MySQL, MariaDB, and SQLite
- **Custom Names**: Respects configured table names

### Manual Migration Control

```go
// Check if migration is needed
err := auth.AutoMigrate()
if err != nil {
    log.Fatal("Migration failed:", err)
}
```

### Database Schema

#### Users Table

```sql
CREATE TABLE users (
    id VARCHAR(36) PRIMARY KEY,
    username VARCHAR(255),
    first_name VARCHAR(255),
    last_name VARCHAR(255),
    email VARCHAR(255),
    avatar_url TEXT,
    roles TEXT NOT NULL DEFAULT '[]',
    metadata TEXT NOT NULL DEFAULT '{}',
    options TEXT NOT NULL DEFAULT '{}',
    password VARCHAR(255),
    created_at DATETIME,
    updated_at DATETIME,
    deleted_at DATETIME
);
```

#### Sessions Table

```sql
CREATE TABLE sessions (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(255),
    ip_address VARCHAR(100),
    user_agent TEXT,
    expires_at DATETIME,
    method VARCHAR(255) DEFAULT 'credentials',
    created_at DATETIME,
    updated_at DATETIME,
    deleted_at DATETIME
);
```

#### Storage Items Table (for social auth)

```sql
CREATE TABLE storage_items (
    key VARCHAR(255) PRIMARY KEY,
    value BLOB,
    expires_at DATETIME,
    created_at DATETIME,
    updated_at DATETIME
);
```

## 🌐 Social Authentication

The service supports multiple OAuth2 providers:

- **Google** - Google OAuth2
- **GitHub** - GitHub OAuth2
- **Apple** - Sign in with Apple
- **Azure AD** - Microsoft Azure Active Directory
- **Azure AD v2** - Microsoft Azure AD v2
- **Passkey** - WebAuthn/FIDO2 passkey authentication

### Social Auth Example

```go
import (
    "github.com/izetmolla/fiberauth/social"
    "github.com/izetmolla/fiberauth/social/providers/google"
)

// Configure Google provider
googleProvider := google.New(&google.Config{
    ClientID:     "your-google-client-id",
    ClientSecret: "your-google-client-secret",
    RedirectURL:  "http://localhost:3000/auth/google/callback",
})

config := &fiberauth.Config{
    JWTSecret: "your-secret-key",
    DbClient:  db,
    Providers: []social.Provider{googleProvider},
}

auth, err := fiberauth.New(config)

// Social auth routes
app.Get("/auth/google", auth.ProviderLoginController)
app.Get("/auth/google/callback", auth.ProviderCallBackController)
```

## 🔍 Error Handling

The service returns structured error responses:

```json
{
  "error": {
    "message": "Validation failed",
    "field": "email"
  }
}
```

### Error Types

- `ErrInvalidCredentials` - Invalid email/password combination
- `ErrUserNotFound` - User does not exist
- `ErrUserAlreadyExists` - User already registered
- `ErrInvalidToken` - Invalid or malformed token
- `ErrTokenExpired` - Token has expired
- `ErrUnauthorized` - User is not authorized

## 📋 Configuration Reference

### Complete Config Example

```go
config := &fiberauth.Config{
    // Core
    JWTSecret:   "your-super-secret-jwt-key",
    Debug:       true,
    DbClient:    db,
    RedisClient: redis,
    
    // Tokens
    AccessTokenLifetime:  stringPtr("30m"),
    RefreshTokenLifetime: stringPtr("7d"),
    SigningMethodHMAC:    stringPtr("HS256"),
    
    // Redis
    RedisKeyPrefix: "MYAPP_SESSIONS",
    RedisTTL:       durationPtr(30 * time.Minute),
    
    // Password
    PasswordCost:      intPtr(12),
    PasswordMinLength: intPtr(8),
    
    // Cookies
    CookieSessionName: stringPtr("app_session"),
    MainDomainName:    stringPtr("example.com"),
    AuthRedirectURL:   stringPtr("https://app.example.com"),
    
    // Tables
    UsersModelTable:   "app_users",
    SessionModelTable: "app_sessions",
    StorageTableName:  "app_storage",
    
    // Paths
    SignInPath:           "/api/auth/login",
    SignUpPath:           "/api/auth/register",
    SignOutPath:          "/api/auth/logout",
    RefreshTokenPath:     "/api/auth/refresh",
    ProviderLoginPath:    "/api/auth/:provider",
    ProviderCallbackPath: "/api/auth/:provider/callback",
    ProviderLogoutPath:   "/api/auth/:provider/logout",
    
    // Social providers
    Providers: []social.Provider{googleProvider, githubProvider},
}

func stringPtr(s string) *string { return &s }
func intPtr(i int) *int { return &i }
func durationPtr(d time.Duration) *time.Duration { return &d }
```

## 🚀 Performance Considerations

- **Redis Caching**: Session data is cached in Redis for fast access
- **Database Queries**: Uses efficient GORM queries with proper indexing
- **Connection Pooling**: Leverages GORM's connection pooling
- **Cross-Database**: Optimized queries work efficiently across all databases
- **Model-Based Queries**: Uses GORM model-style queries for optimal performance
- **Thread-Safe**: Table name registry uses mutex for concurrent access

## 🧪 Testing

The service includes comprehensive test coverage. Run tests with:

```bash
go test ./...
```

For verbose output:

```bash
go test -v ./...
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📝 Changelog

### Latest Features (v1.0.46+)

- ✅ **Cross-Database Support** - Full support for MySQL, MariaDB, PostgreSQL, and SQLite
- ✅ **Custom Table Names** - Configure table names for users, sessions, and storage items
- ✅ **Auto-Migration** - Automatic table creation and schema migration on initialization
- ✅ **Custom API Paths** - Configurable endpoint paths for all authentication routes
- ✅ **SQLite Compatibility** - Fixed UUID and JSON type handling for SQLite
- ✅ **Table Name Registry** - Dynamic table name resolution using thread-safe registry
- ✅ **Storage Table Configuration** - Custom storage table name support for social auth
- ✅ **Model-Based Queries** - Replaced raw SQL with GORM model-style queries for cross-database compatibility
- ✅ **BeforeCreate Hooks** - Automatic UUID generation and default value handling

### Breaking Changes

None - all changes are backward compatible.

### Migration Guide

If you're upgrading from an older version:

1. **Custom Table Names**: You can now configure table names via `Config.UsersModelTable` and `Config.SessionModelTable`
2. **SQLite Users**: The service now works seamlessly with SQLite without manual schema changes
3. **Custom Paths**: Use `Config.SignInPath`, `Config.SignUpPath`, etc. to customize API endpoints

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](../../LICENSE) file for details.
