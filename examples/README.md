# Authorization Package Examples

This directory contains comprehensive examples demonstrating how to use the authorization package for various authentication and authorization scenarios.

## 📁 Examples Structure

```
examples/
├── README.md                    # This documentation file
├── basic-auth/                  # Basic authentication examples
│   ├── main.go                 # Simple sign-in/sign-up example
│   └── README.md               # Basic auth documentation
├── social-auth/                 # Social authentication examples
│   ├── main.go                 # OAuth provider examples
│   ├── google-auth.go          # Google OAuth example
│   └── README.md               # Social auth documentation
├── middleware/                  # Middleware usage examples
│   ├── main.go                 # JWT and role-based middleware
│   ├── jwt-middleware.go       # JWT authentication middleware
│   └── README.md               # Middleware documentation
├── session-management/          # Session handling examples
│   ├── main.go                 # Session creation and management
│   └── README.md               # Session documentation
├── error-handling/             # Error handling examples
│   ├── main.go                 # Error handling patterns
│   └── README.md               # Error handling documentation
└── integration/                # Full integration examples
    ├── main.go                 # Complete application example
    └── README.md               # Integration documentation
```

## 🚀 Quick Start

### Prerequisites

1. **Go 1.21+** - Required for the authorization package
2. **PostgreSQL** - For user data storage
3. **Redis** - For session management (optional)
4. **Environment Variables** - Configure your secrets

### Environment Setup

Create a `.env` file in your project root:

```bash
# Database Configuration
POSTGRES_URL=postgres://username:password@localhost:5432/auth_db

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-here

# Redis Configuration (optional)
REDIS_URL=redis://localhost:6379

# Domain Configuration
AUTH_DOMAIN=example.com
AUTH_REDIRECT_URL=https://example.com/callback

# Social Providers (optional)
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret
```

### Basic Usage

```go
package main

import (
    "log"
    "github.com/izetmolla/fiberauth"
)

func main() {
    // Initialize authorization service
    config := &fiberauth.Config{
        JWTSecret: "your-secret-key",
        Debug:     true,
    }
    
    auth, err := fiberauth.New(config)
    if err != nil {
        log.Fatal(err)
    }
    
    // Use the authorization service
    // ... see examples below
}
```

## 📚 Example Categories

### 1. Basic Authentication

**Location**: `basic-auth/`

Demonstrates fundamental authentication operations:
- User registration (sign-up)
- User login (sign-in)
- Password validation
- Token management

**Key Features**:
- Email/password authentication
- JWT token generation
- Password hashing with bcrypt
- Input validation

### 2. Social Authentication

**Location**: `social-auth/`

Shows how to integrate OAuth providers:
- Google OAuth
- GitHub OAuth
- Custom provider integration
- Social user profile handling

**Key Features**:
- OAuth 2.0 flow
- Social user creation
- Profile data mapping
- Provider management

### 3. Middleware Usage

**Location**: `middleware/`

Demonstrates middleware integration:
- JWT authentication middleware
- Role-based access control
- Route protection
- Custom middleware creation

**Key Features**:
- Automatic token validation
- Role checking
- Route protection
- Error handling

### 4. Session Management

**Location**: `session-management/`

Shows session handling capabilities:
- Session creation
- Cookie management
- Session storage
- Session validation

**Key Features**:
- Secure cookie handling
- Session persistence
- Session cleanup
- Multi-device support

### 5. Error Handling

**Location**: `error-handling/`

Demonstrates error handling patterns:
- Validation errors
- Authentication errors
- Field-specific errors
- Error response formatting

**Key Features**:
- Structured error responses
- Field-level error reporting
- Error logging
- Client-friendly messages

### 6. Full Integration

**Location**: `integration/`

Complete application example:
- Full authentication flow
- Database integration
- Redis integration
- Production-ready setup

**Key Features**:
- Complete workflow
- Best practices
- Production considerations
- Performance optimization

## 🔧 Configuration Options

### Authorization Config

```go
type Config struct {
    // Core settings
    JWTSecret   string `json:"jwt_secret" yaml:"jwt_secret"`
    Debug       bool   `json:"debug" yaml:"debug"`
    
    // Database settings
    DbClient    *gorm.DB
    RedisClient *redis.Client
    
    // Domain settings
    AuthURL     string `json:"auth_url" yaml:"auth_url"`
    AuthDomain  string `json:"auth_domain" yaml:"auth_domain"`
    
    // Social providers
    Providers   map[string]social.Provider
}
```

### Environment Variables

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `JWT_SECRET` | Secret key for JWT signing | ✅ | - |
| `POSTGRES_URL` | PostgreSQL connection string | ✅ | - |
| `REDIS_URL` | Redis connection string | ❌ | - |
| `AUTH_DOMAIN` | Application domain | ❌ | localhost |
| `AUTH_REDIRECT_URL` | OAuth redirect URL | ❌ | - |
| `DEBUG` | Enable debug mode | ❌ | false |

## 🛠️ Common Use Cases

### 1. User Registration

```go
// Create a new user
signUpReq := &fiberauth.SignUpRequest{
    FirstName: "John",
    LastName:  "Doe",
    Email:     "john@example.com",
    Password:  "securepassword123",
}

response, err := auth.SignUp(signUpReq)
if err != nil {
    // Handle validation errors
    if errorFields, ok := err.(*fiberauth.ErrorFields); ok {
        fmt.Printf("Field error: %s - %s\n", errorFields.Field, errorFields.Error)
    }
    return
}

// User created successfully
fmt.Printf("User ID: %s\n", response.User.(map[string]interface{})["id"])
fmt.Printf("Access Token: %s\n", response.Tokens.AccessToken)
```

### 2. User Login

```go
// Authenticate user
signInReq := &fiberauth.SignInRequest{
    Email:    "john@example.com",
    Password: "securepassword123",
}

response, err := auth.SignIn(signInReq)
if err != nil {
    // Handle authentication errors
    return
}

// User authenticated successfully
fmt.Printf("Welcome, %s!\n", response.User.(map[string]interface{})["first_name"])
```

### 3. JWT Middleware

```go
// Protect routes with JWT middleware
app.Use(auth.JWTMiddleware())

// Protected route
app.Get("/protected", func(c fiber.Ctx) error {
    user := c.Locals("user").(*jwt.Token)
    return c.JSON(fiber.Map{"message": "Protected data", "user": user.Claims})
})
```

### 4. Role-Based Access

```go
// Check user roles
app.Get("/admin", auth.AllowOnly([]string{"admin"}), func(c fiber.Ctx) error {
    return c.JSON(fiber.Map{"message": "Admin only"})
})
```

## 🔒 Security Best Practices

### 1. Password Security

- Use strong passwords (minimum 8 characters)
- Implement password complexity requirements
- Use bcrypt for password hashing
- Never store plain-text passwords

### 2. JWT Security

- Use strong, unique JWT secrets
- Set appropriate token expiration times
- Validate tokens on every request
- Implement token refresh mechanism

### 3. Session Security

- Use secure, HTTP-only cookies
- Implement CSRF protection
- Set appropriate session timeouts
- Validate sessions on each request

### 4. OAuth Security

- Validate OAuth state parameters
- Verify OAuth provider responses
- Implement proper error handling
- Use HTTPS for all OAuth flows

## 🐛 Troubleshooting

### Common Issues

1. **JWT Secret Not Set**
   ```
   Error: JWT_SECRET secret cannot be empty
   ```
   **Solution**: Set the `JWT_SECRET` environment variable

2. **Database Connection Failed**
   ```
   Error: failed to connect to database
   ```
   **Solution**: Check your `POSTGRES_URL` and database connectivity

3. **Invalid Token**
   ```
   Error: invalid token
   ```
   **Solution**: Ensure tokens are properly formatted and not expired

4. **Social Provider Not Found**
   ```
   Error: provider google not found
   ```
   **Solution**: Configure the social provider in your application

### Debug Mode

Enable debug mode for detailed logging:

```go
config := &fiberauth.Config{
    JWTSecret: "your-secret",
    Debug:     true, // Enable debug logging
}
```

## 📖 API Reference

For detailed API documentation, see the main package documentation:

- [Authorization Interface](https://pkg.go.dev/github.com/izetmolla/fiberauth)
- [Configuration Options](https://pkg.go.dev/github.com/izetmolla/fiberauth#Config)
- [Error Types](https://pkg.go.dev/github.com/izetmolla/fiberauth#ErrorFields)

## 🤝 Contributing

When adding new examples:

1. Follow the existing directory structure
2. Include comprehensive documentation
3. Add tests for your examples
4. Update this README with new examples
5. Follow Go best practices

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](../../LICENSE) file for details.
