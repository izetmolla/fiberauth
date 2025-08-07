# Error Handling Example

This example demonstrates comprehensive error handling patterns for the authorization package, including validation errors, authentication errors, authorization errors, and custom error handling.

## 🎯 Features

- ✅ **Validation Error Handling** - Field-specific validation errors
- ✅ **Authentication Error Handling** - Credential and token errors
- ✅ **Authorization Error Handling** - Permission and role errors
- ✅ **Database Error Handling** - Connection and query errors
- ✅ **Custom Error Handling** - Business logic errors
- ✅ **Error Recovery** - Panic recovery and timeout handling
- ✅ **Structured Error Responses** - Consistent error format
- ✅ **Error Testing** - Validation testing endpoints

## 🚀 Quick Start

### Prerequisites

1. **Go 1.21+** - Required for the authorization package
2. **JWT Secret** - Configure your JWT signing secret
3. **Environment Variables** - Set up your configuration

### Running the Example

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd services/authorization/examples/error-handling
   ```

2. **Set environment variables**:
   ```bash
   export JWT_SECRET="your-super-secret-jwt-key-for-error-handling-example"
   export DEBUG=true
   ```

3. **Run the example**:
   ```bash
   go run main.go
   ```

4. **Test the endpoints**:
   ```bash
   # Health check
   curl http://localhost:8082/health
   
   # Validation errors
   curl http://localhost:8082/errors/validation
   
   # Authentication errors
   curl http://localhost:8082/errors/authentication
   
   # Test validation
   curl -X POST http://localhost:8082/errors/test-validation \
     -H "Content-Type: application/json" \
     -d '{
       "email": "invalid-email",
       "password": "123",
       "first_name": "",
       "last_name": ""
     }'
   ```

## 📋 API Endpoints

### Error Demonstration Endpoints

| Method | Endpoint | Description | Response Type |
|--------|----------|-------------|---------------|
| `GET` | `/errors/validation` | Validation error examples | Multiple field errors |
| `GET` | `/errors/authentication` | Authentication error examples | Credential errors |
| `GET` | `/errors/authorization` | Authorization error examples | Permission errors |
| `GET` | `/errors/database` | Database error examples | Connection errors |
| `GET` | `/errors/custom` | Custom error examples | Business logic errors |
| `POST` | `/errors/test-validation` | Test validation errors | Field-specific errors |

### Error Recovery Endpoints

| Method | Endpoint | Description | Response Type |
|--------|----------|-------------|---------------|
| `GET` | `/recovery/panic` | Panic recovery example | Panic simulation |
| `GET` | `/recovery/timeout` | Timeout error example | Timeout simulation |
| `GET` | `/recovery/resource` | Resource error example | Resource simulation |

### Utility Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Health check |

## 🔧 Error Types

### 1. Validation Errors

**Purpose**: Handle input validation errors with field-specific information.

**Example Response**:
```json
{
  "error": true,
  "message": "Validation failed",
  "errors": [
    {
      "error": "email is required",
      "field": "email"
    },
    {
      "error": "password must be at least 6 characters",
      "field": "password"
    },
    {
      "error": "first name is required",
      "field": "first_name"
    }
  ]
}
```

**Implementation**:
```go
func (e *ErrorHandlingExample) handleValidationError(c fiber.Ctx) error {
    validationErrors := []*fiberauth.ErrorFields{
        {
            Error: errors.New("email is required"),
            Field: "email",
        },
        {
            Error: errors.New("password must be at least 6 characters"),
            Field: "password",
        },
    }

    return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
        "error":   true,
        "message": "Validation failed",
        "errors":  validationErrors,
    })
}
```

### 2. Authentication Errors

**Purpose**: Handle authentication and credential errors.

**Example Response**:
```json
{
  "error": true,
  "message": "Authentication failed",
  "field": "password",
  "details": "invalid credentials"
}
```

**Implementation**:
```go
func (e *ErrorHandlingExample) handleAuthenticationError(c fiber.Ctx) error {
    authError := &fiberauth.ErrorFields{
        Error: fiberauth.ErrInvalidCredentials,
        Field: "password",
    }

    return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
        "error":   true,
        "message": "Authentication failed",
        "field":   authError.Field,
        "details": authError.Error.Error(),
    })
}
```

### 3. Authorization Errors

**Purpose**: Handle permission and role-based access errors.

**Example Response**:
```json
{
  "error": true,
  "message": "Insufficient permissions",
  "required_roles": ["admin"],
  "user_roles": ["user"],
  "details": "User does not have required admin role"
}
```

### 4. Database Errors

**Purpose**: Handle database connection and query errors.

**Example Response**:
```json
{
  "error": true,
  "message": "Database error occurred",
  "details": "connection to database failed",
  "code": "DB_CONNECTION_FAILED"
}
```

### 5. Custom Errors

**Purpose**: Handle business logic and custom application errors.

**Example Response**:
```json
{
  "error": true,
  "code": "BUSINESS_RULE_VIOLATION",
  "message": "User quota exceeded",
  "details": "User has exceeded their monthly quota of 1000 requests"
}
```

## 🛡️ Error Handling Patterns

### 1. Structured Error Responses

All errors follow a consistent structure:

```json
{
  "error": true,
  "message": "Human-readable error message",
  "field": "field_name",           // Optional: for field-specific errors
  "details": "Detailed error info", // Optional: for additional context
  "code": "ERROR_CODE"             // Optional: for error categorization
}
```

### 2. Field-Specific Errors

For validation errors, use the `ErrorFields` struct:

```go
type ErrorFields struct {
    Error error  `json:"error"`
    Field string `json:"field,omitempty"`
}
```

### 3. Error Status Codes

Use appropriate HTTP status codes:

- `400 Bad Request` - Validation errors
- `401 Unauthorized` - Authentication errors
- `403 Forbidden` - Authorization errors
- `404 Not Found` - Resource not found
- `408 Request Timeout` - Timeout errors
- `500 Internal Server Error` - Server errors
- `507 Insufficient Storage` - Resource errors

### 4. Error Recovery

Implement proper error recovery mechanisms:

```go
// Panic recovery
defer func() {
    if r := recover(); r != nil {
        log.Printf("Recovered from panic: %v", r)
        // Handle panic recovery
    }
}()
```

## 🔍 Error Testing

### Manual Testing

1. **Start the server**:
   ```bash
   go run main.go
   ```

2. **Test validation errors**:
   ```bash
   curl -X POST http://localhost:8082/errors/test-validation \
     -H "Content-Type: application/json" \
     -d '{
       "email": "invalid-email",
       "password": "123",
       "first_name": "",
       "last_name": ""
     }'
   ```

3. **Test authentication errors**:
   ```bash
   curl http://localhost:8082/errors/authentication
   ```

4. **Test authorization errors**:
   ```bash
   curl http://localhost:8082/errors/authorization
   ```

5. **Test custom errors**:
   ```bash
   curl http://localhost:8082/errors/custom
   ```

### Validation Testing

The `/errors/test-validation` endpoint allows you to test validation with real data:

**Valid Request**:
```bash
curl -X POST http://localhost:8082/errors/test-validation \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "password123",
    "first_name": "John",
    "last_name": "Doe"
  }'
```

**Response**:
```json
{
  "success": true,
  "message": "Validation passed",
  "data": {
    "email": "test@example.com",
    "password": "password123",
    "first_name": "John",
    "last_name": "Doe"
  }
}
```

**Invalid Request**:
```bash
curl -X POST http://localhost:8082/errors/test-validation \
  -H "Content-Type: application/json" \
  -d '{
    "email": "invalid-email",
    "password": "123",
    "first_name": "",
    "last_name": ""
  }'
```

**Response**:
```json
{
  "error": true,
  "message": "Validation failed",
  "errors": [
    {
      "error": "invalid email format",
      "field": "email"
    },
    {
      "error": "password must be at least 6 characters",
      "field": "password"
    },
    {
      "error": "first_name is required",
      "field": "first_name"
    },
    {
      "error": "last_name is required",
      "field": "last_name"
    }
  ]
}
```

## 🔧 Configuration

### Environment Variables

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `JWT_SECRET` | JWT signing secret | ✅ | - |
| `DEBUG` | Enable debug mode | ❌ | false |

### Custom Error Handling

```go
// Custom error handler
app := fiber.New(fiber.Config{
    ErrorHandler: func(c fiber.Ctx, err error) error {
        code := fiber.StatusInternalServerError
        if e, ok := err.(*fiber.Error); ok {
            code = e.Code
        }

        return c.Status(code).JSON(fiber.Map{
            "error":   true,
            "message": err.Error(),
        })
    },
})
```

## 📚 Code Structure

```
error-handling/
├── main.go           # Main application file
└── README.md         # This documentation
```

### Key Components

1. **ErrorHandlingExample**: Main application struct
2. **setupRoutes()**: Route configuration
3. **handleValidationError()**: Validation error handler
4. **handleAuthenticationError()**: Authentication error handler
5. **handleAuthorizationError()**: Authorization error handler
6. **handleCustomError()**: Custom error handler
7. **CustomBusinessError**: Custom error type

## 🚀 Production Considerations

### 1. Error Logging

- Implement structured logging
- Log errors with context
- Use appropriate log levels
- Include request IDs

### 2. Error Monitoring

- Set up error tracking
- Monitor error rates
- Alert on critical errors
- Track error trends

### 3. Security

- Don't expose sensitive information
- Sanitize error messages
- Use appropriate status codes
- Implement rate limiting

### 4. Performance

- Handle errors efficiently
- Avoid expensive error handling
- Cache error responses
- Monitor error impact

## 🔄 Error Handling Best Practices

### 1. Consistent Error Format

Always use a consistent error response format:

```json
{
  "error": true,
  "message": "Human-readable message",
  "code": "ERROR_CODE",
  "details": "Additional context"
}
```

### 2. Field-Specific Errors

For validation errors, include field information:

```json
{
  "error": true,
  "message": "Validation failed",
  "errors": [
    {
      "field": "email",
      "message": "Invalid email format"
    }
  ]
}
```

### 3. Appropriate Status Codes

Use the correct HTTP status codes:

- `400` - Client errors (validation, bad request)
- `401` - Authentication required
- `403` - Authorization denied
- `404` - Resource not found
- `500` - Server errors

### 4. Error Context

Provide enough context for debugging:

```json
{
  "error": true,
  "message": "Database connection failed",
  "code": "DB_CONNECTION_FAILED",
  "details": "Connection timeout after 30 seconds",
  "timestamp": "2024-01-01T00:00:00Z"
}
```

## 🤝 Contributing

When contributing to this example:

1. Follow Go best practices
2. Add comprehensive tests
3. Update documentation
4. Follow error handling guidelines
5. Test thoroughly

## 📄 License

This example is licensed under the MIT License - see the [LICENSE](../../../../LICENSE) file for details.
