# Changelog

## v2.0.0 - Modular Architecture (2025-12-27)

### Major Changes

#### 🏗️ Architecture Refactoring
- **BREAKING**: Restructured into modular `pkg/` packages
- Introduced clean dependency isolation
- Implemented facade pattern for main API
- Added interface-based design for better testability

#### 📦 New Package Structure
- `pkg/config` - Configuration types and defaults
- `pkg/credentials` - Password management (bcrypt isolated)
- `pkg/errors` - Error definitions with wrapping
- `pkg/session` - Session and cookie management
- `pkg/storage` - Data persistence layer
  - `models/` - GORM models
  - `database/` - Database operations
  - `redis/` - Optional Redis caching
- `pkg/tokens` - JWT token operations
- `pkg/utils` - Utilities (sanitization, logging, view)
- `pkg/validation` - Enhanced input validation
- `pkg/core` - Core constants

#### 🔒 Security Enhancements
- Added input sanitization for all user inputs
- Enhanced password strength validation
- Constant-time string comparison for sensitive operations
- Security headers helper functions
- Audit logging support
- Better error messages (prevents user enumeration)
- Truncation of inputs to prevent database issues

#### ✨ New Features
- **Options Pattern**: Functional options for cleaner configuration
- **Logger Interface**: Pluggable logging system
- **Audit Logging**: Security event tracking
- **Enhanced Validation**: More validation rules
- **Error Wrapping**: Better error context with `%w`
- **Security Config**: Centralized security settings

#### 📚 Documentation
- Removed AI-generated docs, kept essentials
- Created comprehensive `GUIDE.md`
- Updated `examples/README.md`
- Added `pkg/README.md` for package docs
- Better godoc comments with examples

#### 🎯 API Improvements
- Cleaner imports - use only what you need
- Better error handling
- More intuitive method names
- Interface-based design (`AuthService`)
- Backward compatible re-exports

### Migration Guide

#### Old Import (Still Works)
```go
import "github.com/izetmolla/fiberauth"

auth, err := fiberauth.New(&fiberauth.Config{
    JWTSecret: "secret",
    DbClient:  db,
})
```

#### New Features Available
```go
// With options pattern
auth, err := fiberauth.New(&fiberauth.Config{
    JWTSecret: "secret",
    DbClient:  db,
},
    fiberauth.WithDebug(true),
    fiberauth.WithPasswordPolicy(14, 10),
)

// With interfaces
var authService fiberauth.AuthService = auth
```

### Breaking Changes

1. **Private Fields**: Internal fields are now private (use getters)
2. **Test Helpers**: Some test helpers moved to `test_helpers.go`
3. **Package Structure**: Old files removed, use new `pkg/` structure

### What Stayed the Same

- ✅ Main API (`SignIn`, `SignUp`, `SignOut`)
- ✅ Middleware API (`UseAuth`)
- ✅ Controller methods
- ✅ `social/` folder (unchanged)
- ✅ `jwt/` folder (unchanged)

### Upgrade Steps

1. Update imports if using internal packages
2. Use test helpers for private method access
3. Update tests to use public API
4. Enjoy improved modularity!

## v1.x - Previous Versions

See git history for previous changes.

