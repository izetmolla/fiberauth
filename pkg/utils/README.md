# Utils Package - Generic Utilities

The `utils` package provides generic utility functions for type conversions and JSON handling that improve type safety and reduce code duplication.

## Generic Functions

### `Convert[TFrom, TTo]`

Converts between two compatible types using JSON marshaling/unmarshaling. This is useful for converting between similar struct types (e.g., `SessionData` to `redis.SessionData`).

**Signature:**
```go
func Convert[TFrom, TTo any](from *TFrom) (*TTo, error)
```

**Example:**
```go
import "github.com/izetmolla/fiberauth/pkg/utils"

// Convert SessionData to redis.SessionData
sessionData := &SessionData{
    ID:     "session-123",
    UserID: "user-456",
    Roles:  []byte(`["admin"]`),
}

redisSession, err := utils.Convert[SessionData, redis.SessionData](sessionData)
if err != nil {
    // Handle error
}

// redisSession is now of type *redis.SessionData
```

### `EnsureJSON[T]`

Ensures a JSON field is not empty, returning a default value if needed. This is useful for handling nullable JSON fields in database models.

**Signature:**
```go
func EnsureJSON[T any](field json.RawMessage, defaultValue T) json.RawMessage
```

**Example:**
```go
import "github.com/izetmolla/fiberauth/pkg/utils"
import "encoding/json"

var user models.User

// Ensure roles field has a default empty array
roles := utils.EnsureJSON(user.Roles, []string{})
// Returns: json.RawMessage(`[]`) if user.Roles is empty
// Returns: user.Roles if it's not empty

// Ensure metadata field has a default empty object
metadata := utils.EnsureJSON(user.Metadata, map[string]any{})
// Returns: json.RawMessage(`{}`) if user.Metadata is empty
// Returns: user.Metadata if it's not empty

// Use in struct initialization
sessionData := &SessionData{
    ID:       sessionID,
    UserID:   user.ID,
    Roles:    utils.EnsureJSON(user.Roles, []string{}),
    Metadata: utils.EnsureJSON(user.Metadata, map[string]any{}),
    Options:  utils.EnsureJSON(user.Options, map[string]any{}),
}
```

### `ParseJSON[T]`

Parses a JSON raw message into the target type with a default fallback if parsing fails or data is empty.

**Signature:**
```go
func ParseJSON[T any](data json.RawMessage, defaultValue T) T
```

**Example:**
```go
import "github.com/izetmolla/fiberauth/pkg/utils"
import "encoding/json"

var user models.User

// Parse roles JSON into []string
roles := utils.ParseJSON[[]string](user.Roles, []string{})
// Returns: []string{} if parsing fails or user.Roles is empty
// Returns: parsed []string if successful

// Parse metadata JSON into map[string]any
metadata := utils.ParseJSON[map[string]any](user.Metadata, map[string]any{})
// Returns: map[string]any{} if parsing fails or user.Metadata is empty
// Returns: parsed map[string]any if successful

// Use in validation or processing
if len(roles) > 0 {
    for _, role := range roles {
        fmt.Printf("User has role: %s\n", role)
    }
}
```

## Type Safety Benefits

These generic functions provide several benefits:

1. **Type Safety**: Compile-time type checking instead of runtime assertions
2. **Code Reusability**: Works with any compatible types
3. **Default Handling**: Built-in support for default values
4. **Error Handling**: Clear error messages when conversions fail

## Common Patterns

### Converting Between Session Types

```go
// SessionData to redis.SessionData
redisSession, err := utils.Convert[SessionData, redis.SessionData](sessionData)
if err != nil {
    log.Printf("Conversion error: %v", err)
    return err
}
```

### Handling Nullable JSON Fields

```go
// Always have a valid default for JSON fields
roles := utils.EnsureJSON(user.Roles, []string{})
metadata := utils.EnsureJSON(user.Metadata, map[string]any{})
options := utils.EnsureJSON(user.Options, map[string]any{})
```

### Parsing with Fallback

```go
// Safe parsing with defaults
roles := utils.ParseJSON[[]string](user.Roles, []string{})
if len(roles) == 0 {
    // Handle empty roles case
}
```

