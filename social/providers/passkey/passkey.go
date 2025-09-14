// Package passkey implements the WebAuthn protocol for authenticating users through passkeys.
// This package provides passwordless authentication using WebAuthn credentials.
package passkey

import (
	"fmt"
	"net/http"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/izetmolla/fiberauth/social"
	"golang.org/x/oauth2"
)

// New creates a new Passkey provider, and sets up important connection details.
// You should always call `passkey.New` to get a new Provider. Never try to create
// one manually.
func New(relyingParty, origin, callbackURL string) *Provider {
	p := &Provider{
		RelyingParty: relyingParty,
		Origin:       origin,
		CallbackURL:  callbackURL,
		providerName: "passkey",
	}

	// Initialize WebAuthn configuration
	wconfig := &webauthn.Config{
		RPDisplayName: "FiberAuth",
		RPID:          relyingParty,
		RPOrigins:     []string{origin},
	}

	webAuthn, err := webauthn.New(wconfig)
	if err != nil {
		// For now, we'll continue without WebAuthn but log the error
		// In production, you might want to handle this differently
		fmt.Printf("Warning: Failed to initialize WebAuthn: %v\n", err)
	}
	p.webAuthn = webAuthn

	return p
}

// Provider is the implementation of `social.Provider` for accessing Passkey/WebAuthn.
type Provider struct {
	RelyingParty string
	Origin       string
	CallbackURL  string
	HTTPClient   *http.Client
	webAuthn     *webauthn.WebAuthn
	providerName string
}

// WebAuthnUser represents a user for WebAuthn authentication
type WebAuthnUser struct {
	ID          []byte
	Name        string
	DisplayName string
	Credentials []webauthn.Credential
}

// WebAuthnID returns the user's ID
func (u *WebAuthnUser) WebAuthnID() []byte {
	return u.ID
}

// WebAuthnName returns the user's username
func (u *WebAuthnUser) WebAuthnName() string {
	return u.Name
}

// WebAuthnDisplayName returns the user's display name
func (u *WebAuthnUser) WebAuthnDisplayName() string {
	return u.DisplayName
}

// WebAuthnCredentials returns the user's credentials
func (u *WebAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	return u.Credentials
}

// WebAuthnIcon returns the user's icon URL
func (u *WebAuthnUser) WebAuthnIcon() string {
	return ""
}

// Name is the name used to retrieve this provider later.
func (p *Provider) Name() string {
	return p.providerName
}

// SetName is to update the name of the provider (needed in case of multiple providers of 1 type)
func (p *Provider) SetName(name string) {
	p.providerName = name
}

// Client returns an HTTP client to be used in all fetch operations.
func (p *Provider) Client() *http.Client {
	return social.HTTPClientWithFallBack(p.HTTPClient)
}

// Debug is a no-op for the passkey package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth initiates the WebAuthn authentication process.
func (p *Provider) BeginAuth(state string) (social.Session, error) {
	// For WebAuthn, we create a session with challenge data
	// This is different from OAuth flows as it doesn't redirect to an external URL
	// Instead, it returns challenge data that the client will use with the WebAuthn API

	session := &Session{
		Challenge: state + "_challenge", // Simple challenge generation for demo
		UserID:    state,
	}

	return session, nil
}

// passkeyUser represents the user data structure for passkey authentication
type passkeyUser struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	Name      string `json:"name"`
	FirstName string `json:"given_name"`
	LastName  string `json:"family_name"`
	Picture   string `json:"picture"`
}

// FetchUser will process the WebAuthn authentication response and return user information.
func (p *Provider) FetchUser(session social.Session) (social.User, error) {
	sess := session.(*Session)
	user := social.User{
		AccessToken: sess.AccessToken,
		Provider:    p.Name(),
	}

	if sess.UserID == "" {
		return user, fmt.Errorf("%s cannot get user information without user ID", p.providerName)
	}

	// In a real implementation, you would:
	// 1. Verify the WebAuthn assertion response
	// 2. Look up the user from your database based on the credential
	// 3. Return the user information

	// For now, we'll create a basic user structure from session data
	user.UserID = sess.UserID
	user.Name = sess.UserName
	user.Email = sess.UserEmail
	user.Provider = p.Name()

	// Store the raw passkey data
	user.RawData = make(map[string]any)
	user.RawData["challenge"] = sess.Challenge
	user.RawData["user_id"] = sess.UserID
	user.RawData["credential_id"] = sess.CredentialID

	return user, nil
}

// RefreshTokenAvailable returns false as passkeys don't use refresh tokens
func (p *Provider) RefreshTokenAvailable() bool {
	return false
}

// RefreshToken is not applicable for WebAuthn/Passkey authentication
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	return nil, fmt.Errorf("refresh token is not supported by passkey authentication")
}

// BeginRegistration starts the passkey registration process
func (p *Provider) BeginRegistration(userID, userName, userDisplayName string) (interface{}, *webauthn.SessionData, error) {
	if p.webAuthn == nil {
		return nil, nil, fmt.Errorf("WebAuthn not initialized")
	}

	user := &WebAuthnUser{
		ID:          []byte(userID),
		Name:        userName,
		DisplayName: userDisplayName,
		Credentials: []webauthn.Credential{},
	}

	options, sessionData, err := p.webAuthn.BeginRegistration(user)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to begin WebAuthn registration: %w", err)
	}

	return options, sessionData, nil
}

// FinishRegistration completes the passkey registration process
func (p *Provider) FinishRegistration(user *WebAuthnUser, sessionData webauthn.SessionData, response *http.Request) (*webauthn.Credential, error) {
	if p.webAuthn == nil {
		return nil, fmt.Errorf("WebAuthn not initialized")
	}

	credential, err := p.webAuthn.FinishRegistration(user, sessionData, response)
	if err != nil {
		return nil, fmt.Errorf("failed to finish WebAuthn registration: %w", err)
	}

	return credential, nil
}

// FinishLogin completes the passkey authentication process
func (p *Provider) FinishLogin(user *WebAuthnUser, sessionData webauthn.SessionData, response *http.Request) (*webauthn.Credential, error) {
	if p.webAuthn == nil {
		return nil, fmt.Errorf("WebAuthn not initialized")
	}

	credential, err := p.webAuthn.FinishLogin(user, sessionData, response)
	if err != nil {
		return nil, fmt.Errorf("failed to finish WebAuthn login: %w", err)
	}

	return credential, nil
}

// SetRelyingParty sets the relying party for WebAuthn
func (p *Provider) SetRelyingParty(rp string) {
	p.RelyingParty = rp
}

// SetOrigin sets the origin for WebAuthn
func (p *Provider) SetOrigin(origin string) {
	p.Origin = origin
}
