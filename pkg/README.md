# FiberAuth Internal Packages

This directory contains modular internal packages for the FiberAuth authentication system.

## 📦 Packages

### `config/`
Configuration types and default values.

**Files:**
- `types.go` - Configuration structs, request/response types
- `defaults.go` - Default values and constants

**Dependencies**: Minimal (only type dependencies)

**Import**: `github.com/izetmolla/fiberauth/pkg/config`

---

### `credentials/`
Password hashing and validation using bcrypt.

**Files:**
- `password.go` - Password manager

**Dependencies**: `golang.org/x/crypto/bcrypt`

**Import**: `github.com/izetmolla/fiberauth/pkg/credentials`

**Usage:**
```go
pm := credentials.NewPasswordManager(12)
hash, _ := pm.HashPassword("password")
isValid := pm.IsValidPassword(hash, "password")
```

---

### `errors/`
Standard error definitions.

**Files:**
- `errors.go` - Error types

**Dependencies**: None

**Import**: `github.com/izetmolla/fiberauth/pkg/errors`

**Usage:**
```go
if err != nil {
    return errors.ErrUnauthorized
}
```

---

### `session/`
Session and cookie management.

**Files:**
- `session.go` - Session manager

**Dependencies**: `gofiber/fiber`

**Import**: `github.com/izetmolla/fiberauth/pkg/session`

**Usage:**
```go
sm := session.NewManager("session_id", "localhost")
sm.SetSessionCookie(c, "session-123")
```

---

### `storage/models/`
GORM data models.

**Files:**
- `user.go` - User model
- `session.go` - Session model

**Dependencies**: `gorm`, `uuid`

**Import**: `github.com/izetmolla/fiberauth/pkg/storage/models`

**Usage:**
```go
user := &models.User{
    Email: "user@example.com",
    // ...
}
```

---

### `storage/database/`
Database operations using GORM.

**Files:**
- `database.go` - Database manager

**Dependencies**: `gorm`, `pkg/storage/models`

**Import**: `github.com/izetmolla/fiberauth/pkg/storage/database`

**Usage:**
```go
dbMgr := database.NewManager(db, "users", "sessions")
user, _ := dbMgr.FindUserByID("user-id")
```

---

### `storage/redis/`
Redis caching for sessions (optional).

**Files:**
- `redis.go` - Redis manager

**Dependencies**: `github.com/redis/go-redis/v9`

**Import**: `github.com/izetmolla/fiberauth/pkg/storage/redis`

**Usage:**
```go
redisMgr := redis.NewManager(client, "prefix", ttl)
session, _ := redisMgr.GetSession("session-id")
```

---

### `tokens/`
JWT token generation and validation.

**Files:**
- `jwt.go` - Token manager

**Dependencies**: `golang-jwt/jwt`

**Import**: `github.com/izetmolla/fiberauth/pkg/tokens`

**Usage:**
```go
tm := tokens.NewManager(secret, "15m", "7d", "HS256")
access, refresh, _ := tm.GenerateJWT(&tokens.JWTOptions{
    UserID: "user-id",
})
```

---

### `utils/`
Utility functions.

**Files:**
- `view.go` - HTML rendering

**Dependencies**: `text/template`

**Import**: `github.com/izetmolla/fiberauth/pkg/utils`

**Usage:**
```go
html := utils.RenderRedirectHTML(map[string]any{
    "jsData": jsonData,
})
```

---

### `validation/`
Input validation utilities.

**Files:**
- `validation.go` - Validator

**Dependencies**: None

**Import**: `github.com/izetmolla/fiberauth/pkg/validation`

**Usage:**
```go
v := validation.NewValidator()
v.MinPasswordLength = 8
err := v.ValidateEmail("user@example.com")
```

---

### `core/`
Core constants and types.

**Files:**
- `constants.go` - Shared constants

**Dependencies**: None

**Import**: `github.com/izetmolla/fiberauth/pkg/core`

---

## 🎯 Design Principles

### 1. Single Responsibility
Each package has one clear purpose.

### 2. Minimal Dependencies
Import only what's needed for that package.

### 3. No Circular Dependencies
Clean dependency graph.

### 4. Interface-Based
Easy to mock and test.

### 5. Encapsulation
Internal details hidden.

---

## 📝 Usage Philosophy

### Don't Import Directly
❌ **Don't do this:**
```go
import "github.com/izetmolla/fiberauth/pkg/tokens"
import "github.com/izetmolla/fiberauth/pkg/session"
// ... manually wiring everything
```

### Use the Facade
✅ **Do this instead:**
```go
import "github.com/izetmolla/fiberauth"

auth, _ := fiberauth.New(&fiberauth.Config{
    JWTSecret: "secret",
    DbClient:  db,
})
// Everything wired automatically
```

### Why?
- The facade (`auth.go`) handles all the wiring
- You get a clean, simple API
- Internal packages can change without breaking your code
- Best practices enforced automatically

---

## 🔍 When to Import pkg/ Directly

### Rarely Needed
Most users should **never** import `pkg/` packages directly.

### Valid Use Cases
1. **Custom Integration**: Building your own auth system
2. **Testing**: Need specific package functionality
3. **Extension**: Adding custom features
4. **Advanced Usage**: Special requirements

### Example: Custom Token Manager
```go
import "github.com/izetmolla/fiberauth/pkg/tokens"

// Create custom token manager with special settings
tm := tokens.NewManager(
    "secret",
    "5m",   // Very short access token
    "30d",  // Long refresh token
    "HS512", // Stronger algorithm
)
```

---

## 🧪 Testing

### Package Tests
```bash
# Test individual packages
go test ./pkg/validation
go test ./pkg/tokens
go test ./pkg/credentials
```

### Integration Tests
```bash
# Test main package
go test -v
```

### Coverage
```bash
# Generate coverage report
go test -cover ./...
```

---

## 🔧 Development

### Adding New Features

1. **Identify the right package**
   - Auth logic? → Root `auth_*.go`
   - Storage? → `pkg/storage/`
   - Validation? → `pkg/validation/`
   - Tokens? → `pkg/tokens/`

2. **Keep it modular**
   - Don't add dependencies unnecessarily
   - Keep packages focused
   - Use interfaces

3. **Update facade**
   - Add method to `Authorization` struct
   - Export types if needed
   - Update documentation

### Example: Adding Email Verification

```go
// 1. Add to pkg/validation/validation.go
func (v *Validator) ValidateEmailVerificationCode(code string) error {
    // validation logic
}

// 2. Add to auth_credentials.go
func (a *Authorization) VerifyEmail(code string) error {
    return a.validator.ValidateEmailVerificationCode(code)
}

// 3. Add controller to auth_controllers.go
func (a *Authorization) VerifyEmailController(c fiber.Ctx) error {
    // controller logic
}
```

---

## 📖 Further Reading

- **Architecture**: See `../ARCHITECTURE.md`
- **Quick Start**: See `../QUICK_START.md`
- **Examples**: See `../examples/README.md`
- **Testing**: See `../TESTING_NOTES.md`

---

## 🎯 Summary

These packages provide the **modular foundation** for FiberAuth.

**Key Points:**
- ✅ Each package is focused and minimal
- ✅ Dependencies are isolated
- ✅ Easy to test independently
- ✅ Professional Go structure
- ✅ Production ready

**Remember:**
- Use the facade (`fiberauth.New()`) for normal usage
- Import `pkg/` packages only for advanced use cases
- Keep packages modular when adding features

---

**Happy Coding!** 🚀

