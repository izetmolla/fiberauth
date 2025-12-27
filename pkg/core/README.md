# Core Package - Authentication Lifecycle Hooks

The `core` package defines callback types for authentication lifecycle events, allowing you to extend and customize the authentication flow without modifying the core library.

## Hook Types

### Authentication Hooks

#### `BeforeSignInCallback`
Called before a user signs in. Returning an error will prevent the sign-in from proceeding.

```go
type BeforeSignInCallback func(*config.SignInRequest) error
```

#### `AfterSignInCallback`
Called after a successful sign-in. Errors are logged but don't affect the sign-in result.

```go
type AfterSignInCallback func(*models.User, *config.AuthorizationResponse) error
```

#### `BeforeSignUpCallback`
Called before a user signs up. Returning an error will prevent the sign-up from proceeding.

```go
type BeforeSignUpCallback func(*config.SignUpRequest) error
```

#### `AfterSignUpCallback`
Called after a successful sign-up. Errors are logged but don't affect the sign-up result.

```go
type AfterSignUpCallback func(*models.User, *config.AuthorizationResponse) error
```

### User Lifecycle Hooks

#### `BeforeUserCreateCallback`
Called before a user is created. The user struct can be modified before creation.

```go
type BeforeUserCreateCallback func(*models.User) error
```

#### `AfterUserCreateCallback`
Called after a user is created.

```go
type AfterUserCreateCallback func(*models.User) error
```

### Token Hooks

#### `BeforeTokenGenerationCallback`
Allows modifying JWT options before token generation. Return modified options or error to prevent token generation.

```go
type BeforeTokenGenerationCallback func(*models.User) (*tokens.JWTOptions, error)
```

#### `AfterTokenGenerationCallback`
Called after tokens are generated.

```go
type AfterTokenGenerationCallback func(*models.User, *config.Tokens) error
```

### Session Hooks

#### `BeforeSessionCreateCallback`
Called before a session is created. Returning an error will prevent session creation.

```go
type BeforeSessionCreateCallback func(*models.User, string) error
```

#### `AfterSessionCreateCallback`
Called after a session is created.

```go
type AfterSessionCreateCallback func(*config.SessionData) error
```

## Usage

See the main [Hooks Documentation](../../HOOKS.md) for complete usage examples.

