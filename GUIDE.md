# FiberAuth - Complete Guide

## 🚀 Quick Start

### Installation
```bash
go get github.com/izetmolla/fiberauth
```

### Minimal Setup
```go
package main

import (
    "github.com/gofiber/fiber/v3"
    "github.com/izetmolla/fiberauth"
    "gorm.io/driver/sqlite"
    "gorm.io/gorm"
)

func main() {
    // Initialize database
    db, _ := gorm.Open(sqlite.Open("auth.db"), &gorm.Config{})

    // Initialize FiberAuth
    auth, _ := fiberauth.New(&fiberauth.Config{
        JWTSecret: "your-secret-key",
        DbClient:  db,
    })

    // Create Fiber app
    app := fiber.New()

    // Auth routes
    app.Post("/auth/signup", auth.SignUpController)
    app.Post("/auth/signin", auth.SignInController)

    // Protected route
    app.Get("/profile", auth.UseAuth(&fiberauth.AuthConfig{
        OnlyAPI: true,
    }), func(c fiber.Ctx) error {
        return c.JSON(fiber.Map{"message": "Protected!"})
    })

    app.Listen(":3000")
}
```

## 📦 Architecture

### Modular Structure
```
pkg/
├── config/          # Configuration types
├── credentials/     # Password management
├── errors/          # Error definitions
├── session/         # Session management
├── storage/         # Data persistence
│   ├── models/      # GORM models
│   ├── database/    # Database operations
│   └── redis/       # Redis caching (optional)
├── tokens/          # JWT operations
├── utils/           # Utilities
├── validation/      # Input validation
└── core/            # Constants
```

### Import Only What You Need
- No Redis? Don't import Redis
- No Social? Don't import OAuth
- Just database + JWT by default

## 🔐 Features

- ✅ JWT token authentication
- ✅ Session-based authentication
- ✅ Role-based access control (RBAC)
- ✅ Password hashing (bcrypt)
- ✅ Redis caching (optional)
- ✅ Social OAuth (optional)
- ✅ Cross-database support (PostgreSQL, MySQL, SQLite)
- ✅ Secure by default
- ✅ Professional Go structure

## 📖 Usage

### Configuration
```go
auth, err := fiberauth.New(&fiberauth.Config{
    // Required
    JWTSecret: "your-secret-key",
    DbClient:  db,

    // Optional - Redis caching
    RedisClient: redisClient,

    // Optional - Token lifetimes
    AccessTokenLifetime:  &"15m",
    RefreshTokenLifetime: &"7d",

    // Optional - Password policy
    PasswordCost:      &12,
    PasswordMinLength: &8,

    // Optional - Social providers
    Providers: []interface{}{
        google.New(clientID, secret, callback, scopes...),
    },
})
```

### Middleware
```go
// JWT authentication
app.Use(auth.UseAuth(&fiberauth.AuthConfig{
    OnlyAPI: true,
}))

// Session authentication with redirect
app.Use(auth.UseAuth(&fiberauth.AuthConfig{
    OnlyAPI:          false,
    RedirectToSignIn: true,
}))

// Role-based access control
app.Use(auth.UseAuth(&fiberauth.AuthConfig{
    OnlyAPI: true,
    Roles:   []string{"admin"},
}))
```

## 📚 Examples

Check the `examples/` directory for complete working examples:

1. **minimal/** - Simplest setup
2. **with-redis/** - Production caching
3. **with-social/** - OAuth integration
4. **rbac/** - Role-based access
5. **production-ready/** - Full production setup

## 🔒 Security

- Passwords hashed with bcrypt (configurable cost)
- JWT tokens with configurable expiration
- Session expiration enforced
- Input sanitization and validation
- SQL injection prevention (GORM)
- Generic error messages (prevents user enumeration)
- Secure cookie settings (HttpOnly, Secure)

## 🧪 Testing

```bash
go test ./...
```

## 📄 License

See LICENSE file

## 🤝 Contributing

Contributions welcome! Please open an issue first to discuss changes.

## 📞 Support

- Check examples/ directory
- Read this guide
- Open an issue for bugs

