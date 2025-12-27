// Package fiberauth provides hook registration methods for authentication lifecycle events.
package fiberauth

import (
	"github.com/izetmolla/fiberauth/pkg/core"
)

// Hook registration methods for authentication lifecycle events

// OnBeforeSignIn registers a callback that is called before a user signs in.
// Returning an error from the callback will prevent the sign-in from proceeding.
//
// Example:
//
//	auth.OnBeforeSignIn(func(req *SignInRequest) error {
//	    // Custom validation or logging
//	    if req.Email == "blocked@example.com" {
//	        return errors.New("this email is blocked")
//	    }
//	    return nil
//	})
func (a *Authorization) OnBeforeSignIn(callback core.BeforeSignInCallback) {
	a.hooks.BeforeSignIn = append(a.hooks.BeforeSignIn, callback)
}

// OnAfterSignIn registers a callback that is called after a successful sign-in.
// Errors are logged but don't affect the sign-in result.
//
// Example:
//
//	auth.OnAfterSignIn(func(user *User, response *AuthorizationResponse) error {
//	    // Audit logging
//	    log.Printf("User %s signed in successfully", user.Email)
//	    return nil
//	})
func (a *Authorization) OnAfterSignIn(callback core.AfterSignInCallback) {
	a.hooks.AfterSignIn = append(a.hooks.AfterSignIn, callback)
}

// OnBeforeSignUp registers a callback that is called before a user signs up.
// Returning an error from the callback will prevent the sign-up from proceeding.
//
// Example:
//
//	auth.OnBeforeSignUp(func(req *SignUpRequest) error {
//	    // Custom validation
//	    if !isValidDomain(req.Email) {
//	        return errors.New("invalid email domain")
//	    }
//	    return nil
//	})
func (a *Authorization) OnBeforeSignUp(callback core.BeforeSignUpCallback) {
	a.hooks.BeforeSignUp = append(a.hooks.BeforeSignUp, callback)
}

// OnAfterSignUp registers a callback that is called after a successful sign-up.
// Errors are logged but don't affect the sign-up result.
//
// Example:
//
//	auth.OnAfterSignUp(func(user *User, response *AuthorizationResponse) error {
//	    // Send welcome email
//	    return sendWelcomeEmail(user.Email)
//	})
func (a *Authorization) OnAfterSignUp(callback core.AfterSignUpCallback) {
	a.hooks.AfterSignUp = append(a.hooks.AfterSignUp, callback)
}

// OnBeforeUserCreate registers a callback that is called before a user is created.
// The user struct can be modified before creation.
//
// Example:
//
//	auth.OnBeforeUserCreate(func(user *User) error {
//	    // Set default values
//	    user.Metadata = json.RawMessage(`{"source": "api"}`)
//	    return nil
//	})
func (a *Authorization) OnBeforeUserCreate(callback core.BeforeUserCreateCallback) {
	a.hooks.BeforeUserCreate = append(a.hooks.BeforeUserCreate, callback)
}

// OnAfterUserCreate registers a callback that is called after a user is created.
//
// Example:
//
//	auth.OnAfterUserCreate(func(user *User) error {
//	    // Create related records
//	    return createUserProfile(user.ID)
//	})
func (a *Authorization) OnAfterUserCreate(callback core.AfterUserCreateCallback) {
	a.hooks.AfterUserCreate = append(a.hooks.AfterUserCreate, callback)
}

// OnBeforeTokenGeneration registers a callback that allows modifying JWT options before token generation.
// Return modified options or error to prevent token generation.
//
// Example:
//
//	auth.OnBeforeTokenGeneration(func(user *User) (*tokens.JWTOptions, error) {
//	    // Add custom claims
//	    return &tokens.JWTOptions{
//	        UserID: user.ID,
//	        Metadata: json.RawMessage(`{"custom": "claim"}`),
//	    }, nil
//	})
func (a *Authorization) OnBeforeTokenGeneration(callback core.BeforeTokenGenerationCallback) {
	a.hooks.BeforeTokenGen = append(a.hooks.BeforeTokenGen, callback)
}

// OnAfterTokenGeneration registers a callback that is called after tokens are generated.
//
// Example:
//
//	auth.OnAfterTokenGeneration(func(user *User, tokens *Tokens) error {
//	    // Store token metadata
//	    return storeTokenMetadata(user.ID, tokens.AccessToken)
//	})
func (a *Authorization) OnAfterTokenGeneration(callback core.AfterTokenGenerationCallback) {
	a.hooks.AfterTokenGen = append(a.hooks.AfterTokenGen, callback)
}

// OnBeforeSessionCreate registers a callback that is called before a session is created.
// Returning an error will prevent session creation.
func (a *Authorization) OnBeforeSessionCreate(callback core.BeforeSessionCreateCallback) {
	a.hooks.BeforeSession = append(a.hooks.BeforeSession, callback)
}

// OnAfterSessionCreate registers a callback that is called after a session is created.
func (a *Authorization) OnAfterSessionCreate(callback core.AfterSessionCreateCallback) {
	a.hooks.AfterSession = append(a.hooks.AfterSession, callback)
}

