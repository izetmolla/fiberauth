// Package core provides core types and interfaces for authentication lifecycle hooks.
package core

import (
	"github.com/izetmolla/fiberauth/pkg/config"
	"github.com/izetmolla/fiberauth/pkg/storage/models"
	"github.com/izetmolla/fiberauth/pkg/tokens"
)

// Callback types for authentication lifecycle events

// BeforeSignInCallback is called before a user signs in.
// Returning an error will prevent the sign-in from proceeding.
type BeforeSignInCallback func(*config.SignInRequest) error

// AfterSignInCallback is called after a successful sign-in.
// Errors are logged but don't affect the sign-in result.
type AfterSignInCallback func(*models.User, *config.AuthorizationResponse) error

// BeforeSignUpCallback is called before a user signs up.
// Returning an error will prevent the sign-up from proceeding.
type BeforeSignUpCallback func(*config.SignUpRequest) error

// AfterSignUpCallback is called after a successful sign-up.
// Errors are logged but don't affect the sign-up result.
type AfterSignUpCallback func(*models.User, *config.AuthorizationResponse) error

// BeforeTokenGenerationCallback allows modifying JWT options before token generation.
// Return modified options or error to prevent token generation.
type BeforeTokenGenerationCallback func(*models.User) (*tokens.JWTOptions, error)

// AfterTokenGenerationCallback is called after tokens are generated.
type AfterTokenGenerationCallback func(*models.User, *config.Tokens) error

// BeforeSessionCreateCallback is called before a session is created.
// Returning an error will prevent session creation.
type BeforeSessionCreateCallback func(*models.User, string) error

// AfterSessionCreateCallback is called after a session is created.
type AfterSessionCreateCallback func(*config.SessionData) error

// BeforeUserCreateCallback is called before a user is created.
// The user struct can be modified before creation.
type BeforeUserCreateCallback func(*models.User) error

// AfterUserCreateCallback is called after a user is created.
type AfterUserCreateCallback func(*models.User) error

// Hooks manages all authentication lifecycle hooks.
type Hooks struct {
	BeforeSignIn        []BeforeSignInCallback
	AfterSignIn         []AfterSignInCallback
	BeforeSignUp        []BeforeSignUpCallback
	AfterSignUp         []AfterSignUpCallback
	BeforeTokenGen      []BeforeTokenGenerationCallback
	AfterTokenGen       []AfterTokenGenerationCallback
	BeforeSession       []BeforeSessionCreateCallback
	AfterSession        []AfterSessionCreateCallback
	BeforeUserCreate    []BeforeUserCreateCallback
	AfterUserCreate     []AfterUserCreateCallback
}

// NewHooks creates a new Hooks instance.
func NewHooks() *Hooks {
	return &Hooks{
		BeforeSignIn:     []BeforeSignInCallback{},
		AfterSignIn:      []AfterSignInCallback{},
		BeforeSignUp:     []BeforeSignUpCallback{},
		AfterSignUp:      []AfterSignUpCallback{},
		BeforeTokenGen:   []BeforeTokenGenerationCallback{},
		AfterTokenGen:    []AfterTokenGenerationCallback{},
		BeforeSession:    []BeforeSessionCreateCallback{},
		AfterSession:     []AfterSessionCreateCallback{},
		BeforeUserCreate: []BeforeUserCreateCallback{},
		AfterUserCreate:  []AfterUserCreateCallback{},
	}
}

