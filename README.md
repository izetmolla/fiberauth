# Authorization Service

A comprehensive authentication and authorization service for Go applications using Fiber framework.

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
    "gorm.io/gorm"
    "github.com/izetmolla/fiberauth"
)

func main() {
    // Initialize Fiber app
    app := fiber.New()

    // Initialize database and Redis clients
    db := initDatabase()    // Your database initialization
    redis := initRedis()    // Your Redis initialization

    // Initialize authorization service with storage
    config := &fiberauth.Config{
        JWTSecret:   "your-super-secret-jwt-key",
        Debug:       true,
        DbClient:    db,
        RedisClient: redis,
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
    JWTSecret   string          // JWT signing secret (required)
    Debug       bool            // Enable debug mode
    DbClient    *gorm.DB        // Database client (optional)
    RedisClient redis.UniversalClient // Redis client (optional)
}
```

## 🛡️ Security Features

- ✅ **JWT Authentication** - Secure token-based authentication
- ✅ **Password Hashing** - Bcrypt password hashing
- ✅ **Session Management** - Server-side session tracking
- ✅ **Input Validation** - Comprehensive request validation
- ✅ **Error Handling** - Structured error responses
- ✅ **Role-Based Access** - Role-based authorization

## 📚 Examples

For more detailed examples, see the [examples](./examples/) folder:

- [Basic Authentication](./examples/basic-auth/) - Complete authentication workflow
- [Middleware Usage](./examples/middleware/) - JWT and role-based middleware
- [Error Handling](./examples/error-handling/) - Comprehensive error handling

## 🔍 Error Handling

The service returns structured error responses:

```json
{
  "error": true,
  "message": "Validation failed",
  "field": "email",
  "details": "invalid email format"
}
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](../../LICENSE) file for details.
