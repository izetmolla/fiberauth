# Hooks Example

This example demonstrates how to use authentication lifecycle hooks in FiberAuth.

## Features Demonstrated

- **BeforeSignIn** - Rate limiting and validation
- **AfterSignIn** - Audit logging and analytics
- **BeforeSignUp** - Email domain validation
- **AfterSignUp** - Welcome emails and user setup
- **BeforeUserCreate** - Setting default values
- **AfterUserCreate** - Creating related resources
- **BeforeTokenGeneration** - Adding custom claims
- **AfterTokenGeneration** - Token tracking
- **BeforeSessionCreate** - Session validation
- **AfterSessionCreate** - Session analytics

## Running the Example

```bash
cd examples/hooks
go run main.go
```

The server will start on `http://localhost:3000`.

## Testing the Hooks

### 1. Sign Up (triggers multiple hooks)

```bash
curl -X POST http://localhost:3000/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "password": "securepassword123",
    "first_name": "John",
    "last_name": "Doe"
  }'
```

**Hooks triggered:**
- `OnBeforeSignUp` - Validates email domain
- `OnBeforeUserCreate` - Sets default metadata
- `OnAfterUserCreate` - Creates user profile
- `OnBeforeSessionCreate` - Validates session
- `OnAfterSessionCreate` - Tracks session
- `OnBeforeTokenGeneration` - Adds custom claims
- `OnAfterTokenGeneration` - Stores token metadata
- `OnAfterSignUp` - Sends welcome email

### 2. Sign In (triggers sign-in hooks)

```bash
curl -X POST http://localhost:3000/auth/signin \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "password": "securepassword123"
  }'
```

**Hooks triggered:**
- `OnBeforeSignIn` - Rate limiting check
- `OnAfterSignIn` - Audit logging and analytics

### 3. Access Protected Route

```bash
curl http://localhost:3000/profile \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

## Watch the Console

All hook executions are logged to the console. Watch for messages like:

```
[HOOK] BeforeSignUp: Attempting sign-up for john@example.com
[HOOK] BeforeUserCreate: Setting defaults for user john@example.com
[HOOK] AfterUserCreate: Setting up resources for user user-123
[HOOK] AfterSignUp: New user registered: john@example.com
[EMAIL] Welcome email sent to: john@example.com
```

## Customizing

You can modify the hook implementations in `main.go` to:

- Add your own validation logic
- Integrate with your email service
- Connect to your analytics platform
- Set up user resources in your system
- Add custom security checks

