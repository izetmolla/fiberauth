# Generics and Callbacks Improvement Proposal

This document outlines opportunities to use **generics** and **callbacks** to make the fiberauth module more useful, efficient, and extensible.

## 🎯 Overview

### Goals
1. **Reduce code duplication** using generics
2. **Improve type safety** by replacing `interface{}` with generics
3. **Increase extensibility** with callback hooks
4. **Better developer experience** with cleaner APIs

---

## 1. GENERICS IMPROVEMENTS

### 1.1 Database Query Operations

**Current Issue:** Repetitive query patterns with type assertions

**Files:**
- `pkg/storage/database/database.go`

**Improvements:**

```go
// Generic finder interface
type Finder[T any] interface {
    FindByID(id any) (*T, error)
    FindBy(conditions map[string]any) (*T, error)
}

// Generic database query helper
func QueryOne[T any](db *gorm.DB, tableName string, conditions map[string]any) (*T, error) {
    var result T
    query := db.Table(tableName)
    for key, value := range conditions {
        query = query.Where(key+" = ?", value)
    }
    err := query.First(&result).Error
    if err != nil {
        if errors.Is(err, gorm.ErrRecordNotFound) {
            return nil, fmt.Errorf("%T not found", result)
        }
        return nil, err
    }
    return &result, nil
}

// Usage in Manager
func (m *Manager) FindUserByID(id any) (*models.User, error) {
    return QueryOne[models.User](m.db, m.usersTableName, map[string]any{
        "id": id,
        "deleted_at": nil,
    })
}

func (m *Manager) GetSessionByID(sessionID string, nowTime time.Time) (*models.Session, error) {
    return QueryOne[models.Session](m.db, m.sessionTableName, map[string]any{
        "id": sessionID,
        "expires_at >": nowTime,
        "deleted_at": nil,
    })
}
```

### 1.2 Session Data Conversions

**Current Issue:** Manual conversion between `SessionData`, `redis.SessionData`, `models.Session`

**Files:**
- `auth_session.go`
- `pkg/storage/redis/redis.go`

**Improvements:**

```go
// Generic converter
func Convert[TFrom, TTo any](from *TFrom) (*TTo, error) {
    if from == nil {
        return nil, errors.New("source cannot be nil")
    }
    
    // Use JSON marshaling/unmarshaling for deep copy
    data, err := json.Marshal(from)
    if err != nil {
        return nil, fmt.Errorf("failed to marshal: %w", err)
    }
    
    var to TTo
    if err := json.Unmarshal(data, &to); err != nil {
        return nil, fmt.Errorf("failed to unmarshal: %w", err)
    }
    
    return &to, nil
}

// Usage
func (a *Authorization) setRedisSession(sessionData *SessionData) {
    if a.redisManager != nil {
        redisSessionData, err := Convert[SessionData, redis.SessionData](sessionData)
        if err != nil {
            if a.Debug {
                fmt.Printf("Failed to convert session: %v\n", err)
            }
            return
        }
        if err := a.redisManager.SetSession(redisSessionData); err != nil {
            if a.Debug {
                fmt.Printf("Failed to cache session in Redis: %v\n", err)
            }
        }
    }
}
```

### 1.3 JSON Field Handling

**Current Issue:** Repeated `ensureJSONField` and `FormatRoles` patterns

**Files:**
- `auth_credentials.go`
- `pkg/tokens/jwt.go`

**Improvements:**

```go
// Generic JSON field handler
func EnsureJSON[T any](field json.RawMessage, defaultValue T) json.RawMessage {
    if len(field) == 0 {
        data, _ := json.Marshal(defaultValue)
        return json.RawMessage(data)
    }
    return field
}

// Generic JSON parser with defaults
func ParseJSON[T any](data json.RawMessage, defaultValue T) T {
    if len(data) == 0 {
        return defaultValue
    }
    var result T
    if err := json.Unmarshal(data, &result); err != nil {
        return defaultValue
    }
    return result
}

// Usage
sessionData := &SessionData{
    ID:       sessionID,
    UserID:   user.ID,
    Roles:    EnsureJSON(user.Roles, []string{}),
    Metadata: EnsureJSON(user.Metadata, map[string]any{}),
    Options:  EnsureJSON(user.Options, map[string]any{}),
}

// Parse roles with generic
roles := ParseJSON[[]string](user.Roles, []string{})
```

### 1.4 Error Handling

**Current Issue:** Repetitive error wrapping patterns

**Files:**
- `pkg/errors/wrap.go`
- Multiple files with similar error handling

**Improvements:**

```go
// Generic error wrapper
func WrapError[T error](err T, context string) error {
    if err == nil {
        return nil
    }
    return fmt.Errorf("%s: %w", context, err)
}

// Generic error handler with default
func HandleError[T any](result T, err error, defaultValue T) T {
    if err != nil {
        return defaultValue
    }
    return result
}
```

---

## 2. CALLBACK IMPROVEMENTS

### 2.1 Authentication Lifecycle Hooks

**Current Issue:** No way to hook into authentication events

**Files:**
- `auth_credentials.go`
- `auth.go`

**Improvements:**

```go
// Callback types
type (
    BeforeSignInCallback    func(*SignInRequest) error
    AfterSignInCallback     func(*models.User, *AuthorizationResponse) error
    BeforeSignUpCallback    func(*SignUpRequest) error
    AfterSignUpCallback     func(*models.User, *AuthorizationResponse) error
    BeforeTokenGenerationCallback func(*models.User) (*tokens.JWTOptions, error)
    AfterTokenGenerationCallback  func(*models.User, *Tokens) error
    BeforeSessionCreateCallback   func(*models.User, string) error
    AfterSessionCreateCallback    func(*SessionData) error
)

// Add to Authorization struct
type Authorization struct {
    // ... existing fields ...
    
    // Lifecycle hooks
    hooks struct {
        beforeSignIn    []BeforeSignInCallback
        afterSignIn     []AfterSignInCallback
        beforeSignUp    []BeforeSignUpCallback
        afterSignUp     []AfterSignUpCallback
        beforeTokenGen  []BeforeTokenGenerationCallback
        afterTokenGen   []AfterTokenGenerationCallback
        beforeSession   []BeforeSessionCreateCallback
        afterSession    []AfterSessionCreateCallback
    }
}

// Hook registration methods
func (a *Authorization) OnBeforeSignIn(callback BeforeSignInCallback) {
    a.hooks.beforeSignIn = append(a.hooks.beforeSignIn, callback)
}

func (a *Authorization) OnAfterSignIn(callback AfterSignInCallback) {
    a.hooks.afterSignIn = append(a.hooks.afterSignIn, callback)
}

// Usage in SignIn
func (a *Authorization) SignIn(request *SignInRequest) (*AuthorizationResponse, *ErrorFields) {
    // Execute before hooks
    for _, hook := range a.hooks.beforeSignIn {
        if err := hook(request); err != nil {
            return nil, &ErrorFields{Error: err}
        }
    }
    
    // ... existing sign in logic ...
    
    response := &AuthorizationResponse{
        User:      userResponse(user),
        SessionID: sessionID,
        Tokens:    *tkns,
    }
    
    // Execute after hooks
    for _, hook := range a.hooks.afterSignIn {
        if err := hook(user, response); err != nil {
            // Log error but don't fail the request
            if a.Debug {
                fmt.Printf("AfterSignIn hook error: %v\n", err)
            }
        }
    }
    
    return response, nil
}
```

### 2.2 User Lifecycle Hooks

**Current Issue:** No way to customize user creation/update

**Files:**
- `auth_credentials.go`
- `auth_social.go`

**Improvements:**

```go
type (
    BeforeUserCreateCallback func(*models.User) error
    AfterUserCreateCallback  func(*models.User) error
    BeforeUserUpdateCallback func(*models.User, map[string]any) error
    AfterUserUpdateCallback  func(*models.User) error
)

func (a *Authorization) OnBeforeUserCreate(callback BeforeUserCreateCallback) {
    a.hooks.beforeUserCreate = append(a.hooks.beforeUserCreate, callback)
}

// Usage
func (a *Authorization) createUser(email string, socialUser *social.User) (*models.User, error) {
    user := &models.User{
        Email:     email,
        FirstName: socialUser.FirstName,
        // ... other fields ...
    }
    
    // Execute before hooks
    for _, hook := range a.hooks.beforeUserCreate {
        if err := hook(user); err != nil {
            return nil, err
        }
    }
    
    if err := a.dbManager.CreateUser(user); err != nil {
        return nil, err
    }
    
    // Execute after hooks
    for _, hook := range a.hooks.afterUserCreate {
        if err := hook(user); err != nil {
            // Log but don't fail
        }
    }
    
    return user, nil
}
```

### 2.3 Custom Validation Rules

**Current Issue:** Validation rules are hardcoded

**Files:**
- `pkg/validation/validation.go`

**Improvements:**

```go
type ValidationRule func(value any, fieldName string) error

type Validator struct {
    MinPasswordLength int
    customRules       map[string][]ValidationRule
}

func (v *Validator) AddRule(fieldName string, rule ValidationRule) {
    if v.customRules == nil {
        v.customRules = make(map[string][]ValidationRule)
    }
    v.customRules[fieldName] = append(v.customRules[fieldName], rule)
}

func (v *Validator) Validate(fieldName string, value any) error {
    if rules, ok := v.customRules[fieldName]; ok {
        for _, rule := range rules {
            if err := rule(value, fieldName); err != nil {
                return err
            }
        }
    }
    return nil
}

// Usage
auth.validator.AddRule("email", func(value any, fieldName string) error {
    email := value.(string)
    if !strings.Contains(email, "@company.com") {
        return fmt.Errorf("email must be from company domain")
    }
    return nil
})
```

### 2.4 Token Generation Hooks

**Current Issue:** Can't customize token claims

**Files:**
- `pkg/tokens/jwt.go`
- `auth.go`

**Improvements:**

```go
type TokenClaimsCallback func(*models.User) map[string]any

func (a *Authorization) OnTokenClaims(callback TokenClaimsCallback) {
    a.hooks.tokenClaims = append(a.hooks.tokenClaims, callback)
}

// Usage in authorize method
func (a *Authorization) authorize(user *models.User, ip, userAgent string, method ...string) (*Tokens, string, error) {
    // ... existing code ...
    
    jwtOpts := &tokens.JWTOptions{
        SessionID: sessionID,
        UserID:    user.ID,
        Metadata:  user.Metadata,
        Roles:     user.Roles,
        Method:    method[0],
    }
    
    // Execute hooks to add custom claims
    for _, hook := range a.hooks.tokenClaims {
        customClaims := hook(user)
        // Merge custom claims into metadata
        // ... implementation ...
    }
    
    accessToken, refreshToken, err := a.tokenManager.GenerateJWT(jwtOpts)
    // ... rest of code ...
}
```

---

## 3. IMPLEMENTATION PRIORITY

### High Priority (Immediate Benefits)
1. ✅ **Generic session data conversions** - Eliminates manual conversion code
2. ✅ **Authentication lifecycle hooks** - Enables event-driven integrations
3. ✅ **Generic JSON field handling** - Reduces repetitive code

### Medium Priority (Good ROI)
4. **Generic database queries** - Better type safety
5. **User lifecycle hooks** - Better extensibility
6. **Custom validation rules** - More flexibility

### Low Priority (Nice to Have)
7. **Generic error handling** - Minor improvement
8. **Token generation hooks** - Advanced use case

---

## 4. EXAMPLE USAGE

### Example 1: Using Hooks for Audit Logging

```go
auth.OnAfterSignIn(func(user *models.User, response *AuthorizationResponse) error {
    log.Printf("User %s signed in at %s", user.Email, time.Now())
    return nil
})

auth.OnBeforeSignUp(func(request *SignUpRequest) error {
    // Custom validation
    if request.Email == "admin@example.com" {
        return errors.New("admin email not allowed")
    }
    return nil
})
```

### Example 2: Using Generics for Custom Models

```go
type CustomUser struct {
    models.User
    CompanyID string `gorm:"type:varchar(36)"`
}

user, err := QueryOne[CustomUser](db, "users", map[string]any{
    "id": userID,
})
```

### Example 3: Using Custom Validation Rules

```go
auth.validator.AddRule("password", func(value any, fieldName string) error {
    password := value.(string)
    // Check against common passwords list
    if isCommonPassword(password) {
        return errors.New("password is too common")
    }
    return nil
})
```

---

## 5. BACKWARD COMPATIBILITY

All proposed changes maintain **100% backward compatibility**:
- Existing APIs remain unchanged
- New features are additive only
- Optional use of generics/callbacks
- Default behavior unchanged if hooks not used

---

## 6. TESTING STRATEGY

1. **Unit tests** for generic functions
2. **Integration tests** for callback hooks
3. **Example tests** showing usage patterns
4. **Performance benchmarks** comparing old vs new

---

## Conclusion

These improvements will make fiberauth:
- **More type-safe** with generics
- **More extensible** with callbacks
- **More maintainable** with less duplication
- **More powerful** for advanced use cases
- **Still simple** for basic usage

