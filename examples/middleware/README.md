# Middleware Example

This example demonstrates how to use middleware for authentication and authorization in your applications, including JWT authentication, role-based access control, and custom middleware.

## 🎯 Features

- ✅ **JWT Authentication Middleware** - Token-based authentication
- ✅ **Role-Based Access Control** - Role-based authorization
- ✅ **Custom Middleware** - Custom middleware implementation
- ✅ **Route Protection** - Protected and public routes
- ✅ **Context Management** - User data in request context
- ✅ **Error Handling** - Structured error responses
- ✅ **Multiple Role Levels** - User, moderator, and admin roles

## 🚀 Quick Start

### Prerequisites

1. **Go 1.21+** - Required for the authorization package
2. **JWT Secret** - Configure your JWT signing secret
3. **Environment Variables** - Set up your configuration

### Running the Example

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd services/authorization/examples/middleware
   ```

2. **Set environment variables**:
   ```bash
   export JWT_SECRET="your-super-secret-jwt-key-for-middleware-example"
   export DEBUG=true
   ```

3. **Run the example**:
   ```bash
   go run main.go
   ```

4. **Test the endpoints**:
   ```bash
   # Health check (no authentication required)
   curl http://localhost:8081/health
   
   # Public information (no authentication required)
   curl http://localhost:8081/public/info
   
   # Protected route (authentication required)
   curl -X GET http://localhost:8081/protected/profile \
     -H "Authorization: Bearer YOUR_JWT_TOKEN"
   ```

## 📋 API Endpoints

### Public Endpoints (No Authentication Required)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Health check |
| `GET` | `/public/info` | Public information |

### Protected Endpoints (Authentication Required)

| Method | Endpoint | Description | Required Roles |
|--------|----------|-------------|----------------|
| `GET` | `/protected/profile` | User profile | Any authenticated user |
| `GET` | `/protected/settings` | User settings | Any authenticated user |

### Admin Endpoints (Admin Role Required)

| Method | Endpoint | Description | Required Roles |
|--------|----------|-------------|----------------|
| `GET` | `/admin/dashboard` | Admin dashboard | `admin` |
| `GET` | `/admin/users` | List all users | `admin` |
| `POST` | `/admin/users` | Create new user | `admin` |

### Moderator Endpoints (Moderator or Admin Role Required)

| Method | Endpoint | Description | Required Roles |
|--------|----------|-------------|----------------|
| `GET` | `/moderator/content` | List content | `moderator`, `admin` |
| `POST` | `/moderator/content/approve` | Approve content | `moderator`, `admin` |

### Custom Middleware Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/custom/data` | Custom middleware data |

## 🔧 Middleware Types

### 1. JWT Authentication Middleware

**Purpose**: Validates JWT tokens and extracts user information.

**Implementation**:
```go
func (m *MiddlewareExample) jwtMiddleware() fiber.Handler {
    return func(c fiber.Ctx) error {
        // Extract token from header
        token, err := m.auth.GetTokenFromHeader(c)
        if err != nil {
            return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
                "error":   true,
                "message": "No valid token provided",
            })
        }

        // Validate token
        claims, err := m.auth.ExtractToken(token)
        if err != nil {
            return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
                "error":   true,
                "message": "Invalid or expired token",
            })
        }

        // Set user information in context
        c.Locals("user_id", claims.UserID)
        c.Locals("session_id", claims.SessionID)
        c.Locals("claims", claims)

        return c.Next()
    }
}
```

**Usage**:
```go
// Apply to route group
protected := app.Group("/protected")
protected.Use(m.jwtMiddleware())
```

### 2. Role-Based Access Control Middleware

**Purpose**: Checks user roles and restricts access based on permissions.

**Implementation**:
```go
func (m *MiddlewareExample) roleMiddleware(requiredRoles []string) fiber.Handler {
    return func(c fiber.Ctx) error {
        // Get user information from context
        userID := c.Locals("user_id")
        if userID == nil {
            return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
                "error":   true,
                "message": "User not authenticated",
            })
        }

        // Get user roles
        userRoles := m.getUserRoles(userID.(string))

        // Check if user has required roles
        if !m.checkUserRoles(requiredRoles, userRoles) {
            return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
                "error":   true,
                "message": "Insufficient permissions",
                "required_roles": requiredRoles,
                "user_roles":     userRoles,
            })
        }

        // Set roles in context
        c.Locals("user_roles", userRoles)
        c.Locals("required_roles", requiredRoles)

        return c.Next()
    }
}
```

**Usage**:
```go
// Apply to admin routes
admin := app.Group("/admin")
admin.Use(m.jwtMiddleware())
admin.Use(m.roleMiddleware([]string{"admin"}))
```

### 3. Custom Middleware

**Purpose**: Demonstrates custom middleware functionality.

**Implementation**:
```go
func (m *MiddlewareExample) customMiddleware() fiber.Handler {
    return func(c fiber.Ctx) error {
        // Add custom headers
        c.Set("X-Custom-Middleware", "enabled")
        c.Set("X-Request-ID", c.Get("X-Request-ID", "default-id"))

        // Log request information
        log.Printf("Custom middleware: %s %s", c.Method(), c.Path())

        // Add custom data to context
        c.Locals("custom_data", fiber.Map{
            "middleware": "custom",
            "timestamp":  "2024-01-01T00:00:00Z",
        })

        return c.Next()
    }
}
```

## 🛡️ Security Features

### 1. Authentication

- **JWT Token Validation**: Automatic token validation
- **Token Extraction**: Support for Bearer tokens
- **Session Management**: Session ID tracking
- **Error Handling**: Proper authentication error responses

### 2. Authorization

- **Role-Based Access**: Multiple role levels (user, moderator, admin)
- **Permission Checking**: Automatic permission validation
- **Context Management**: User data in request context
- **Access Control**: Route-level access control

### 3. Middleware Chain

- **Ordered Execution**: Middleware executes in order
- **Context Passing**: Data passed between middleware
- **Error Propagation**: Errors propagate through chain
- **Performance**: Efficient middleware execution

## 🔍 Error Handling

### Authentication Errors

```json
{
  "error": true,
  "message": "No valid token provided"
}
```

### Authorization Errors

```json
{
  "error": true,
  "message": "Insufficient permissions",
  "required_roles": ["admin"],
  "user_roles": ["user", "moderator"]
}
```

### Validation Errors

```json
{
  "error": true,
  "message": "Invalid request body"
}
```

## 🧪 Testing

### Manual Testing

1. **Start the server**:
   ```bash
   go run main.go
   ```

2. **Test public endpoints**:
   ```bash
   curl http://localhost:8081/health
   curl http://localhost:8081/public/info
   ```

3. **Test protected endpoints** (requires JWT token):
   ```bash
   # Get a JWT token first (from basic-auth example or your auth system)
   curl -X GET http://localhost:8081/protected/profile \
     -H "Authorization: Bearer YOUR_JWT_TOKEN"
   ```

4. **Test admin endpoints** (requires admin role):
   ```bash
   curl -X GET http://localhost:8081/admin/dashboard \
     -H "Authorization: Bearer ADMIN_JWT_TOKEN"
   ```

5. **Test moderator endpoints** (requires moderator role):
   ```bash
   curl -X GET http://localhost:8081/moderator/content \
     -H "Authorization: Bearer MODERATOR_JWT_TOKEN"
   ```

### Role Testing

The example includes predefined user roles for testing:

| User ID | Roles |
|---------|-------|
| `user-1` | `["user"]` |
| `user-2` | `["user", "moderator"]` |
| `user-3` | `["user", "admin"]` |
| `user-4` | `["user", "moderator", "admin"]` |

## 🔧 Configuration

### Environment Variables

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `JWT_SECRET` | JWT signing secret | ✅ | - |
| `DEBUG` | Enable debug mode | ❌ | false |

### Custom Configuration

```go
config := &fiberauth.Config{
    JWTSecret: "your-secret-key",
    Debug:     true,
}

auth, err := fiberauth.New(config)
if err != nil {
    log.Fatal(err)
}
```

## 📚 Code Structure

```
middleware/
├── main.go           # Main application file
└── README.md         # This documentation
```

### Key Components

1. **MiddlewareExample**: Main application struct
2. **setupRoutes()**: Route configuration with middleware
3. **jwtMiddleware()**: JWT authentication middleware
4. **roleMiddleware()**: Role-based access control middleware
5. **customMiddleware()**: Custom middleware example
6. **Handler functions**: Route handlers for different endpoints

## 🚀 Production Considerations

### 1. Security

- Use strong, unique JWT secrets
- Implement rate limiting
- Add request logging
- Use HTTPS in production
- Validate all inputs

### 2. Performance

- Cache user roles
- Optimize middleware chain
- Monitor middleware performance
- Use connection pooling

### 3. Scalability

- Implement distributed sessions
- Use load balancers
- Add horizontal scaling
- Monitor resource usage

### 4. Monitoring

- Add health checks
- Implement logging
- Set up alerts
- Monitor performance

## 🔄 Middleware Order

The order of middleware execution is important:

1. **Global middleware** (app.Use())
2. **Group middleware** (group.Use())
3. **Route-specific middleware** (route.Use())
4. **Route handler**

Example:
```go
// Global middleware
app.Use(logger.New())

// Group middleware
protected := app.Group("/protected")
protected.Use(authMiddleware)
protected.Use(rateLimitMiddleware)

// Route-specific middleware
protected.Get("/profile", profileHandler).Use(cacheMiddleware)
```

## 🤝 Contributing

When contributing to this example:

1. Follow Go best practices
2. Add comprehensive tests
3. Update documentation
4. Follow security guidelines
5. Test thoroughly

## 📄 License

This example is licensed under the MIT License - see the [LICENSE](../../../../LICENSE) file for details.
