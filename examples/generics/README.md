# Generics Example

This example demonstrates how to use the generic utility functions provided by FiberAuth.

## Features Demonstrated

- **Convert[TFrom, TTo]** - Type-safe conversion between compatible types
- **EnsureJSON[T]** - Ensuring JSON fields have default values
- **ParseJSON[T]** - Parsing JSON with type safety and defaults

## Running the Example

```bash
cd examples/generics
go run main.go
```

## What You'll See

The example demonstrates:

1. **Type Conversion** - Converting between `SessionData` and `redis.SessionData` types
2. **JSON Field Handling** - Ensuring empty JSON fields have proper defaults
3. **Safe JSON Parsing** - Parsing JSON with fallback to defaults on errors
4. **Real-world Pattern** - Complete workflow from user to session data

## Code Examples

### Type Conversion

```go
// Convert SessionData to redis.SessionData
sessionData := &fiberauth.SessionData{
    ID:     "session-123",
    UserID: "user-456",
}

redisSession, err := utils.Convert[fiberauth.SessionData, redis.SessionData](sessionData)
```

### Ensuring JSON Defaults

```go
// Ensure empty JSON fields have defaults
roles := utils.EnsureJSON(user.Roles, []string{})
metadata := utils.EnsureJSON(user.Metadata, map[string]any{})
```

### Parsing JSON Safely

```go
// Parse with fallback to defaults
roles := utils.ParseJSON[[]string](user.Roles, []string{})
metadata := utils.ParseJSON[map[string]any](user.Metadata, map[string]any{})
```

## Benefits

These generic functions provide:

- **Type Safety** - Compile-time type checking
- **Code Reusability** - Works with any compatible types
- **Default Handling** - Built-in support for defaults
- **Error Safety** - Graceful handling of parsing errors

