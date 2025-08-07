# Basic Authentication Example

This example demonstrates fundamental authentication operations using the authorization package, including user registration, login, logout, and token management.

## 🎯 Features

- ✅ **User Registration** - Sign up with email and password
- ✅ **User Authentication** - Sign in with credentials
- ✅ **Session Management** - Cookie-based sessions
- ✅ **Token Management** - JWT token generation and refresh
- ✅ **Protected Routes** - Route protection with middleware
- ✅ **Input Validation** - Request validation with field-specific errors
- ✅ **Error Handling** - Structured error responses

## 🚀 Quick Start

### Prerequisites

1. **Go 1.21+** - Required for the authorization package
2. **PostgreSQL** - For user data storage (optional for this example)
3. **Environment Variables** - Configure your secrets

### Running the Example

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd services/authorization/examples/basic-auth
   ```

2. **Set environment variables**:
   ```bash
   export JWT_SECRET="your-super-secret-jwt-key-for-example"
   export DEBUG=true
   ```

3. **Run the example**:
   ```bash
   go run main.go
   ```

4. **Test the endpoints**:
   ```bash
   # Health check
   curl http://localhost:8080/health
   
   # User registration
   curl -X POST http://localhost:8080/auth/signup \
     -H "Content-Type: application/json" \
     -d '{
       "first_name": "John",
       "last_name": "Doe",
       "email": "john@example.com",
       "password": "securepassword123"
     }'
   
   # User login
   curl -X POST http://localhost:8080/auth/signin \
     -H "Content-Type: application/json" \
     -d '{
       "email": "john@example.com",
       "password": "securepassword123"
     }'
   ```

## 📋 API Endpoints

### Authentication Endpoints

| Method | Endpoint | Description | Request Body |
|--------|----------|-------------|--------------|
| `POST` | `/auth/signup` | Register a new user | `SignUpRequest` |
| `POST` | `/auth/signin` | Authenticate user | `SignInRequest` |
| `POST` | `/auth/signout` | Logout user | `SignOutRequest` |
| `POST` | `/auth/refresh` | Refresh access token | - |

### Protected Endpoints

| Method | Endpoint | Description | Authentication |
|--------|----------|-------------|----------------|
| `GET` | `/protected/profile` | Get user profile | Required |
| `GET` | `/protected/dashboard` | Access dashboard | Required |

### Utility Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Health check |

## 🔧 Request/Response Examples

### User Registration

**Request**:
```bash
curl -X POST http://localhost:8080/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "first_name": "John",
    "last_name": "Doe",
    "email": "john@example.com",
    "password": "securepassword123"
  }'
```

**Success Response**:
```json
{
  "success": true,
  "message": "User created successfully",
  "data": {
    "user": {
      "id": "user-123",
      "first_name": "John",
      "last_name": "Doe",
      "email": "john@example.com",
      "roles": [],
      "metadata": {}
    },
    "session_id": "session-456",
    "tokens": {
      "access_token": "eyJhbGciOiJIUzI1NiIs...",
      "refresh_token": "eyJhbGciOiJIUzI1NiIs..."
    }
  }
}
```

**Error Response**:
```json
{
  "error": true,
  "field": "email",
  "message": "email already exists"
}
```

### User Authentication

**Request**:
```bash
curl -X POST http://localhost:8080/auth/signin \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "password": "securepassword123"
  }'
```

**Success Response**:
```json
{
  "success": true,
  "message": "User authenticated successfully",
  "data": {
    "user": {
      "id": "user-123",
      "first_name": "John",
      "last_name": "Doe",
      "email": "john@example.com"
    },
    "session_id": "session-456",
    "tokens": {
      "access_token": "eyJhbGciOiJIUzI1NiIs...",
      "refresh_token": "eyJhbGciOiJIUzI1NiIs..."
    }
  }
}
```

### Protected Route Access

**Request**:
```bash
curl -X GET http://localhost:8080/protected/profile \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIs..."
```

**Success Response**:
```json
{
  "success": true,
  "message": "Profile retrieved successfully",
  "data": {
    "user_id": "user-123",
    "session_id": "session-456"
  }
}
```

## 🛡️ Security Features

### 1. Password Security

- **Bcrypt Hashing**: Passwords are hashed using bcrypt with cost factor 12
- **Password Validation**: Minimum 6 characters required
- **Secure Storage**: Passwords are never stored in plain text

### 2. JWT Security

- **Strong Secrets**: JWT tokens are signed with strong secrets
- **Token Expiration**: Access tokens have configurable expiration
- **Refresh Tokens**: Secure token refresh mechanism
- **Token Validation**: Automatic token validation on protected routes

### 3. Session Security

- **Secure Cookies**: Session cookies are HTTP-only and secure
- **Session Management**: Server-side session tracking
- **CSRF Protection**: Built-in CSRF protection
- **Session Cleanup**: Automatic session cleanup on logout

### 4. Input Validation

- **Field Validation**: Comprehensive input validation
- **Error Messages**: Field-specific error messages
- **Sanitization**: Input sanitization and validation
- **Type Safety**: Strong typing for all requests

## 🔍 Error Handling

### Validation Errors

```json
{
  "error": true,
  "field": "email",
  "message": "invalid email format"
}
```

### Authentication Errors

```json
{
  "error": true,
  "field": "password",
  "message": "invalid credentials"
}
```

### Authorization Errors

```json
{
  "error": true,
  "message": "No valid token provided"
}
```

## 🧪 Testing

### Manual Testing

1. **Start the server**:
   ```bash
   go run main.go
   ```

2. **Test user registration**:
   ```bash
   curl -X POST http://localhost:8080/auth/signup \
     -H "Content-Type: application/json" \
     -d '{
       "first_name": "Test",
       "last_name": "User",
       "email": "test@example.com",
       "password": "password123"
     }'
   ```

3. **Test user login**:
   ```bash
   curl -X POST http://localhost:8080/auth/signin \
     -H "Content-Type: application/json" \
     -d '{
       "email": "test@example.com",
       "password": "password123"
     }'
   ```

4. **Test protected route**:
   ```bash
   # Use the access token from the login response
   curl -X GET http://localhost:8080/protected/profile \
     -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
   ```

### Automated Testing

Run the tests for the authorization package:

```bash
cd ../../..
go test ./services/authorization/...
```

## 🔧 Configuration

### Environment Variables

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `JWT_SECRET` | JWT signing secret | ✅ | - |
| `DEBUG` | Enable debug mode | ❌ | false |
| `POSTGRES_URL` | Database URL | ❌ | - |
| `REDIS_URL` | Redis URL | ❌ | - |

### Custom Configuration

```go
config := &fiberauth.Config{
    JWTSecret: "your-secret-key",
    Debug:     true,
    // Add database and Redis clients if needed
}

auth, err := fiberauth.New(config)
if err != nil {
    log.Fatal(err)
}
```

## 📚 Code Structure

```
basic-auth/
├── main.go           # Main application file
└── README.md         # This documentation
```

### Key Components

1. **BasicAuthExample**: Main application struct
2. **setupRoutes()**: Route configuration
3. **handleSignUp()**: User registration handler
4. **handleSignIn()**: User authentication handler
5. **handleSignOut()**: User logout handler
6. **authMiddleware()**: Authentication middleware
7. **Protected handlers**: Profile and dashboard handlers

## 🚀 Production Considerations

### 1. Security

- Use strong, unique JWT secrets
- Enable HTTPS in production
- Implement rate limiting
- Add request logging
- Use secure cookie settings

### 2. Performance

- Add caching for user data
- Implement connection pooling
- Use CDN for static assets
- Monitor application metrics

### 3. Scalability

- Use load balancers
- Implement horizontal scaling
- Add database clustering
- Use message queues

### 4. Monitoring

- Add health checks
- Implement logging
- Set up alerts
- Monitor performance

## 🤝 Contributing

When contributing to this example:

1. Follow Go best practices
2. Add comprehensive tests
3. Update documentation
4. Follow security guidelines
5. Test thoroughly

## 📄 License

This example is licensed under the MIT License - see the [LICENSE](../../../../LICENSE) file for details.
