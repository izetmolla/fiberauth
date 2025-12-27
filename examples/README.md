# FiberAuth Examples

This directory contains comprehensive examples demonstrating various FiberAuth use cases.

## 📁 Examples Overview

### 1. **Minimal** (`minimal/`)
The simplest possible setup - just database and JWT authentication.

**Features:**
- SQLite database
- No Redis caching
- No social providers
- Basic SignUp/SignIn/SignOut
- JWT token authentication

**Use when:**
- Getting started with FiberAuth
- Building a simple application
- Don't need advanced features

**Run:**
```bash
cd minimal
go run main.go
```

---

### 2. **With Redis** (`with-redis/`)
Production-ready setup with Redis caching for improved performance.

**Features:**
- PostgreSQL database
- Redis session caching
- JWT and session-based auth
- Role-based access control
- Faster session lookups

**Use when:**
- Building a production application
- Need high performance
- Have multiple server instances
- Want session management

**Run:**
```bash
# Start PostgreSQL and Redis
docker-compose up -d

cd with-redis
go run main.go
```

---

### 3. **With Social** (`with-social/`)
OAuth integration with Google and GitHub providers.

**Features:**
- Google OAuth
- GitHub OAuth
- Traditional email/password auth
- Social profile import
- HTML login page

**Use when:**
- Want social login
- Need OAuth integration
- Building consumer-facing apps

**Setup:**
```bash
# Set environment variables
export GOOGLE_CLIENT_ID="your-id"
export GOOGLE_CLIENT_SECRET="your-secret"
export GITHUB_CLIENT_ID="your-id"
export GITHUB_CLIENT_SECRET="your-secret"

cd with-social
go run main.go
```

---

### 4. **RBAC** (`rbac/`)
Complete Role-Based Access Control implementation.

**Features:**
- Multiple role levels (user, moderator, admin, superadmin)
- Role hierarchy
- Route-level protection
- Custom role checking
- Fine-grained permissions

**Use when:**
- Need complex permissions
- Building enterprise applications
- Have different user types
- Need admin panels

**Run:**
```bash
cd rbac
go run main.go
```

---

### 5. **Production Ready** (`production-ready/`)
Full production setup with all best practices.

**Features:**
- PostgreSQL + Redis
- Google OAuth
- Rate limiting
- CORS configuration
- Health checks
- Graceful shutdown
- Error handling
- Logging
- Environment configuration
- Docker ready

**Use when:**
- Deploying to production
- Need enterprise features
- Want best practices
- Require monitoring

**Run:**
```bash
cd production-ready
go run main.go
```

---

### 6. **Basic Auth** (`basic-auth/`)
Original basic authentication example (legacy).

**Features:**
- Simple authentication
- Custom validation
- Error handling

---

### 7. **Error Handling** (`error-handling/`)
Demonstrates proper error handling patterns (legacy).

**Features:**
- Custom error responses
- Validation errors
- HTTP status codes

---

### 8. **Middleware** (`middleware/`)
Shows middleware usage and customization (legacy).

**Features:**
- Custom middleware
- JWT validation
- Protected routes

---

## 🚀 Quick Start Guide

### Choose Your Starting Point:

```bash
# Beginner - Simple setup
cd examples/minimal && go run main.go

# Intermediate - With caching
cd examples/with-redis && go run main.go

# Advanced - With OAuth
cd examples/with-social && go run main.go

# Expert - Production setup
cd examples/production-ready && go run main.go
```

## 📋 Prerequisites

### Minimal Requirements:
- Go 1.21+
- SQLite (built-in)

### With Redis:
- PostgreSQL 13+
- Redis 6+

### With Social:
- OAuth credentials from providers
- Google Cloud Console account
- GitHub OAuth App

### Production:
- Docker & Docker Compose
- PostgreSQL 15+
- Redis 7+
- Reverse proxy (nginx/traefik)

## 🔧 Configuration

### Environment Variables

```bash
# Database
DATABASE_URL="postgres://user:pass@localhost:5432/dbname"

# Redis
REDIS_URL="localhost:6379"

# JWT
JWT_SECRET="your-secret-key-min-32-characters"

# OAuth - Google
GOOGLE_CLIENT_ID="your-google-client-id"
GOOGLE_CLIENT_SECRET="your-google-client-secret"
GOOGLE_REDIRECT_URL="http://localhost:3000/auth/google/callback"

# OAuth - GitHub
GITHUB_CLIENT_ID="your-github-client-id"
GITHUB_CLIENT_SECRET="your-github-client-secret"

# Server
PORT="3000"
ENV="development"
```

## 📚 Learning Path

### Beginner:
1. Start with **Minimal** example
2. Understand basic SignUp/SignIn
3. Test with curl commands
4. Explore JWT tokens

### Intermediate:
1. Move to **With Redis** example
2. Learn about session caching
3. Try **RBAC** for permissions
4. Understand role hierarchies

### Advanced:
1. Implement **With Social** OAuth
2. Configure provider credentials
3. Test OAuth flows
4. Study **Production Ready** example

### Expert:
1. Deploy **Production Ready** setup
2. Configure monitoring
3. Set up CI/CD
4. Implement custom features

## 🧪 Testing Examples

### Using cURL:

```bash
# Sign Up
curl -X POST http://localhost:3000/auth/signup \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"test123","first_name":"Test","last_name":"User"}'

# Sign In
curl -X POST http://localhost:3000/auth/signin \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"test123"}'

# Access Protected Route
curl http://localhost:3000/api/profile \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Using Postman:

1. Import the collection (coming soon)
2. Set environment variables
3. Run authentication flows
4. Test protected endpoints

## 🐛 Common Issues

### Database Connection Failed:
```bash
# Check if PostgreSQL is running
pg_isready

# Check connection string
psql $DATABASE_URL
```

### Redis Connection Failed:
```bash
# Check if Redis is running
redis-cli ping

# Start Redis
redis-server
```

### OAuth Not Working:
- Verify redirect URLs in provider dashboards
- Check environment variables are set
- Ensure correct client ID/secret
- Use HTTPS in production

## 📖 Additional Resources

- [FiberAuth Documentation](../README.md)
- [Architecture Guide](../ARCHITECTURE.md)
- [API Reference](https://pkg.go.dev/github.com/izetmolla/fiberauth)
- [Fiber Framework](https://gofiber.io)

## 🤝 Contributing

Found an issue or have a suggestion? Please open an issue!

Want to add a new example? Pull requests are welcome!

## 📄 License

Same as FiberAuth main package.
