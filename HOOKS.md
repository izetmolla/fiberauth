# Authentication Lifecycle Hooks

FiberAuth provides a comprehensive hook system that allows you to customize and extend the authentication flow without modifying the core library. Hooks are callbacks that are executed at specific points in the authentication lifecycle.

## Table of Contents

- [Getting Started](#getting-started)
- [Hook Types](#hook-types)
- [Examples](#examples)
- [Best Practices](#best-practices)

## Getting Started

All hooks are registered on the `Authorization` instance after creation:

```go
import "github.com/izetmolla/fiberauth"

auth, err := fiberauth.New(&fiberauth.Config{
    JWTSecret: "your-secret-key",
    DbClient:  db,
})

if err != nil {
    log.Fatal(err)
}

// Register hooks
auth.OnAfterSignIn(func(user *fiberauth.User, response *fiberauth.AuthorizationResponse) error {
    log.Printf("User %s signed in", user.Email)
    return nil
})
```

## Hook Types

### Authentication Hooks

#### `OnBeforeSignIn`

Called **before** a user signs in. You can use this for:
- Custom validation
- Rate limiting
- IP blocking
- Request modification

**Important:** Returning an error will **prevent** the sign-in from proceeding.

```go
auth.OnBeforeSignIn(func(request *fiberauth.SignInRequest) error {
    // Block specific emails
    if request.Email == "blocked@example.com" {
        return errors.New("this email is blocked")
    }
    
    // Rate limiting check
    if isRateLimited(request.Email) {
        return errors.New("too many login attempts")
    }
    
    // All checks passed
    return nil
})
```

#### `OnAfterSignIn`

Called **after** a successful sign-in. You can use this for:
- Audit logging
- Analytics tracking
- Welcome notifications
- Session analytics

**Important:** Errors are **logged but don't fail** the sign-in.

```go
auth.OnAfterSignIn(func(user *fiberauth.User, response *fiberauth.AuthorizationResponse) error {
    // Audit logging
    log.Printf("[AUDIT] User %s signed in at %s from IP %s", 
        user.Email, time.Now(), requestIP)
    
    // Send notification (optional)
    go sendLoginNotification(user.Email)
    
    // Analytics
    trackEvent("user.signin", map[string]any{
        "user_id": user.ID,
        "email": user.Email,
    })
    
    return nil
})
```

#### `OnBeforeSignUp`

Called **before** a user signs up. You can use this for:
- Email domain validation
- Username restrictions
- Custom business rules
- Pre-signup checks

**Important:** Returning an error will **prevent** the sign-up from proceeding.

```go
auth.OnBeforeSignUp(func(request *fiberauth.SignUpRequest) error {
    // Validate email domain
    if !strings.HasSuffix(request.Email, "@company.com") {
        return errors.New("only company email addresses are allowed")
    }
    
    // Check username restrictions
    if containsRestrictedWords(request.Username) {
        return errors.New("username contains restricted words")
    }
    
    // Additional validation
    if request.Email == "admin@example.com" {
        return errors.New("admin email cannot be used")
    }
    
    return nil
})
```

#### `OnAfterSignUp`

Called **after** a successful sign-up. You can use this for:
- Welcome emails
- Onboarding setup
- User profile creation
- Analytics tracking

**Important:** Errors are **logged but don't fail** the sign-up.

```go
auth.OnAfterSignUp(func(user *fiberauth.User, response *fiberauth.AuthorizationResponse) error {
    // Send welcome email
    if err := sendWelcomeEmail(user.Email, user.FirstName); err != nil {
        // Log but don't fail
        log.Printf("Failed to send welcome email: %v", err)
    }
    
    // Create user profile
    if err := createUserProfile(user.ID); err != nil {
        log.Printf("Failed to create user profile: %v", err)
    }
    
    // Analytics
    trackEvent("user.signup", map[string]any{
        "user_id": user.ID,
        "email": user.Email,
    })
    
    return nil
})
```

### User Lifecycle Hooks

#### `OnBeforeUserCreate`

Called **before** a user is created in the database. You can use this to:
- Set default values
- Add custom metadata
- Modify user fields
- Validate before creation

**Important:** The user struct can be **modified** before creation.

```go
auth.OnBeforeUserCreate(func(user *fiberauth.User) error {
    // Set default metadata
    user.Metadata = json.RawMessage(`{
        "source": "api",
        "signup_date": "` + time.Now().Format(time.RFC3339) + `",
        "signup_ip": "` + getRequestIP() + `"
    }`)
    
    // Set default roles for new users
    user.Roles = json.RawMessage(`["user"]`)
    
    // Add tracking
    user.Options = json.RawMessage(`{
        "newsletter": false,
        "marketing": false
    }`)
    
    return nil
})
```

#### `OnAfterUserCreate`

Called **after** a user is created in the database. You can use this for:
- Creating related records
- Setting up user resources
- Sending confirmation emails
- Post-creation setup

```go
auth.OnAfterUserCreate(func(user *fiberauth.User) error {
    // Create user profile
    if err := createUserProfile(user.ID); err != nil {
        return err // This will be logged but won't fail the creation
    }
    
    // Create default settings
    if err := createUserSettings(user.ID); err != nil {
        return err
    }
    
    // Initialize user storage
    if err := initializeUserStorage(user.ID); err != nil {
        return err
    }
    
    return nil
})
```

### Token Hooks

#### `OnBeforeTokenGeneration`

Allows modifying JWT options before token generation. You can use this to:
- Add custom claims
- Modify token lifetime
- Set custom metadata

**Important:** Return modified options or error to prevent token generation.

```go
auth.OnBeforeTokenGeneration(func(user *fiberauth.User) (*tokens.JWTOptions, error) {
    // Parse existing metadata
    var metadata map[string]any
    if len(user.Metadata) > 0 {
        json.Unmarshal(user.Metadata, &metadata)
    }
    
    // Add custom claims
    metadata["department"] = getUserDepartment(user.ID)
    metadata["permissions"] = getUserPermissions(user.ID)
    
    // Marshal back
    metadataJSON, _ := json.Marshal(metadata)
    
    // Return modified options
    return &tokens.JWTOptions{
        UserID:    user.ID,
        Metadata:  json.RawMessage(metadataJSON),
        Roles:     user.Roles,
    }, nil
})
```

#### `OnAfterTokenGeneration`

Called after tokens are generated. You can use this for:
- Token tracking
- Security logging
- Token storage
- Analytics

```go
auth.OnAfterTokenGeneration(func(user *fiberauth.User, tokens *fiberauth.Tokens) error {
    // Store token metadata for auditing
    storeTokenMetadata(user.ID, tokens.AccessToken, time.Now())
    
    // Security logging
    log.Printf("[SECURITY] Tokens generated for user %s", user.Email)
    
    return nil
})
```

### Session Hooks

#### `OnBeforeSessionCreate`

Called before a session is created. You can use this for:
- Session validation
- Rate limiting
- Device checking

**Important:** Returning an error will prevent session creation.

```go
auth.OnBeforeSessionCreate(func(user *fiberauth.User, ipAddress string) error {
    // Check device limits
    if hasTooManyActiveSessions(user.ID) {
        return errors.New("too many active sessions")
    }
    
    // Validate IP address
    if isBlockedIP(ipAddress) {
        return errors.New("IP address is blocked")
    }
    
    return nil
})
```

#### `OnAfterSessionCreate`

Called after a session is created. You can use this for:
- Session tracking
- Analytics
- Notifications

```go
auth.OnAfterSessionCreate(func(session *fiberauth.SessionData) error {
    // Track session creation
    trackSessionCreation(session.UserID, session.ID)
    
    // Send security notification if new device
    if isNewDevice(session.UserID) {
        sendSecurityNotification(session.UserID)
    }
    
    return nil
})
```

## Complete Example

Here's a complete example showing multiple hooks in action:

```go
package main

import (
    "encoding/json"
    "log"
    "time"
    
    "github.com/izetmolla/fiberauth"
    "gorm.io/driver/sqlite"
    "gorm.io/gorm"
)

func main() {
    // Setup database
    db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
    if err != nil {
        log.Fatal(err)
    }
    
    // Create auth instance
    auth, err := fiberauth.New(&fiberauth.Config{
        JWTSecret: "your-secret-key",
        DbClient:  db,
        Debug:     true,
    })
    if err != nil {
        log.Fatal(err)
    }
    
    // Register hooks
    
    // Before sign-in: Rate limiting and validation
    auth.OnBeforeSignIn(func(request *fiberauth.SignInRequest) error {
        log.Printf("Attempting sign-in for: %s", request.Email)
        
        if isRateLimited(request.Email) {
            return errors.New("too many login attempts, please try again later")
        }
        
        return nil
    })
    
    // After sign-in: Audit logging and analytics
    auth.OnBeforeSignIn(func(user *fiberauth.User, response *fiberauth.AuthorizationResponse) error {
        log.Printf("[AUDIT] User %s signed in successfully", user.Email)
        
        // Track analytics
        trackEvent("user.signin", map[string]any{
            "user_id": user.ID,
            "timestamp": time.Now(),
        })
        
        return nil
    })
    
    // Before sign-up: Domain validation
    auth.OnBeforeSignUp(func(request *fiberauth.SignUpRequest) error {
        if !strings.HasSuffix(request.Email, "@company.com") {
            return errors.New("only company email addresses allowed")
        }
        return nil
    })
    
    // After sign-up: Welcome email and setup
    auth.OnAfterSignUp(func(user *fiberauth.User, response *fiberauth.AuthorizationResponse) error {
        // Send welcome email
        sendWelcomeEmail(user.Email)
        
        // Create user profile
        createUserProfile(user.ID)
        
        log.Printf("New user registered: %s", user.Email)
        return nil
    })
    
    // Before user create: Set defaults
    auth.OnBeforeUserCreate(func(user *fiberauth.User) error {
        user.Metadata = json.RawMessage(`{
            "source": "api",
            "created_at": "` + time.Now().Format(time.RFC3339) + `"
        }`)
        return nil
    })
    
    // After user create: Setup resources
    auth.OnAfterUserCreate(func(user *fiberauth.User) error {
        // Create user settings
        createUserSettings(user.ID)
        return nil
    })
    
    // Continue with your application...
}
```

## Best Practices

### 1. Error Handling

- **Before hooks**: Return errors to prevent the action
- **After hooks**: Errors are logged but don't fail the operation
- Always log errors for debugging

```go
auth.OnAfterSignIn(func(user *fiberauth.User, response *fiberauth.AuthorizationResponse) error {
    if err := sendNotification(user.Email); err != nil {
        // Log but don't return error (won't fail sign-in)
        log.Printf("Failed to send notification: %v", err)
    }
    return nil // Always return nil for after hooks
})
```

### 2. Performance

- Keep hook functions **fast** - they run synchronously
- Use goroutines for slow operations (emails, external APIs)

```go
auth.OnAfterSignUp(func(user *fiberauth.User, response *fiberauth.AuthorizationResponse) error {
    // Run slow operation in background
    go func() {
        sendWelcomeEmail(user.Email)
        setupUserResources(user.ID)
    }()
    
    return nil
})
```

### 3. Idempotency

- Design hooks to be **idempotent** when possible
- Handle duplicate calls gracefully

```go
auth.OnAfterUserCreate(func(user *fiberauth.User) error {
    // Check if already exists before creating
    if !userProfileExists(user.ID) {
        return createUserProfile(user.ID)
    }
    return nil
})
```

### 4. Security

- Don't log sensitive information
- Validate all inputs
- Use hooks for security checks

```go
auth.OnBeforeSignIn(func(request *fiberauth.SignInRequest) error {
    // Security check
    if isBlockedEmail(request.Email) {
        log.Printf("[SECURITY] Blocked sign-in attempt: %s", request.Email)
        return errors.New("authentication failed")
    }
    return nil
})
```

### 5. Testing

- Test hooks independently
- Mock external dependencies
- Verify hook execution order

```go
func TestSignInHook(t *testing.T) {
    var hookCalled bool
    auth.OnBeforeSignIn(func(request *fiberauth.SignInRequest) error {
        hookCalled = true
        return nil
    })
    
    // Test sign-in
    // Verify hookCalled is true
}
```

## Hook Execution Order

Hooks are executed in the order they are registered:

1. **Sign In Flow:**
   - `OnBeforeSignIn` (all registered)
   - Sign-in logic
   - `OnAfterSignIn` (all registered)

2. **Sign Up Flow:**
   - `OnBeforeSignUp` (all registered)
   - `OnBeforeUserCreate` (all registered)
   - User creation
   - `OnAfterUserCreate` (all registered)
   - `OnBeforeSessionCreate` (all registered)
   - Session creation
   - `OnAfterSessionCreate` (all registered)
   - `OnBeforeTokenGeneration` (all registered)
   - Token generation
   - `OnAfterTokenGeneration` (all registered)
   - `OnAfterSignUp` (all registered)

## Troubleshooting

### Hook Not Firing

- Ensure hook is registered **before** the action occurs
- Check that no earlier hook returned an error
- Verify the hook signature matches exactly

### Performance Issues

- Profile hook execution time
- Move slow operations to background goroutines
- Consider caching for expensive operations

### Debugging

Enable debug mode to see hook execution:

```go
auth, err := fiberauth.New(&fiberauth.Config{
    // ... other config
    Debug: true, // Enable debug logging
})
```

