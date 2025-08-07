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
