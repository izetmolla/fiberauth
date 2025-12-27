# Generics and Hooks Examples

This directory contains examples demonstrating the generics and hooks functionality in FiberAuth.

## Examples

### 1. Hooks Example (`hooks/`)

Demonstrates authentication lifecycle hooks for extending and customizing the authentication flow.

**Key Features:**
- Before/After hooks for sign-in and sign-up
- User lifecycle hooks
- Token generation hooks
- Session management hooks

**Run it:**
```bash
cd examples/hooks
go run main.go
```

See [hooks/README.md](./hooks/README.md) for detailed documentation.

### 2. Generics Example (`generics/`)

Demonstrates generic utility functions for type conversions and JSON handling.

**Key Features:**
- Type-safe conversions between compatible types
- JSON field handling with defaults
- Safe JSON parsing with fallbacks

**Run it:**
```bash
cd examples/generics
go run main.go
```

See [generics/README.md](./generics/README.md) for detailed documentation.

## Documentation

For complete documentation on hooks and generics, see:

- **Hooks**: [../../HOOKS.md](../../HOOKS.md) - Complete hooks documentation
- **Generics**: [../../pkg/utils/README.md](../../pkg/utils/README.md) - Generic utilities documentation
- **Core Types**: [../../pkg/core/README.md](../../pkg/core/README.md) - Hook type definitions

## Quick Start

### Using Hooks

```go
auth, _ := fiberauth.New(&fiberauth.Config{
    JWTSecret: "secret",
    DbClient:  db,
})

// Register hooks
auth.OnAfterSignIn(func(user *fiberauth.User, response *fiberauth.AuthorizationResponse) error {
    log.Printf("User %s signed in", user.Email)
    return nil
})
```

### Using Generics

```go
import "github.com/izetmolla/fiberauth/pkg/utils"

// Convert between types
redisSession, err := utils.Convert[SessionData, redis.SessionData](sessionData)

// Ensure JSON defaults
roles := utils.EnsureJSON(user.Roles, []string{})

// Parse JSON safely
metadata := utils.ParseJSON[map[string]any](user.Metadata, map[string]any{})
```

## Learning Path

1. Start with the **Generics Example** to understand type-safe utilities
2. Then explore the **Hooks Example** to see lifecycle customization
3. Read the full documentation for advanced usage patterns

