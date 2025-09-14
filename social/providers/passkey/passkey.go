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

// Provider is the implementation of `social.Provider` for accessing Passkey/WebAuthn.
type Provider struct {
	ClientKey    string
	Secret       string
	CallbackURL  string
	HTTPClient   *http.Client
	webAuthn     *webauthn.WebAuthn
	providerName string
	relyingParty string
	origin       string
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

// New creates a new Passkey provider, and sets up important connection details.
// You should always call `passkey.New` to get a new Provider. Never try to create
// one manually.
func New(relyingParty, origin, callbackURL string) (*Provider, error) {
	wconfig := &webauthn.Config{
		RPDisplayName: "FiberAuth",
		RPID:          relyingParty,
		RPOrigins:     []string{origin},
	}

	webAuthn, err := webauthn.New(wconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create WebAuthn instance: %w", err)
	}

	return &Provider{
		CallbackURL:  callbackURL,
		webAuthn:     webAuthn,
		providerName: "passkey",
		relyingParty: relyingParty,
		origin:       origin,
	}, nil
}

// Name is the name used to retrieve this provider later.
func (p *Provider) Name() string {
	return p.providerName
}

// SetName is to update the name of the provider (needed in case of multiple providers of 1 type)
func (p *Provider) SetName(name string) {
	p.providerName = name
}

func (p *Provider) Client() *http.Client {
	return social.HTTPClientWithFallBack(p.HTTPClient)
}

// Debug is a no-op for the passkey package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth initiates the WebAuthn authentication process.
func (p *Provider) BeginAuth(state string) (social.Session, error) {
	// For WebAuthn, we need to create a credential request options
	// This is different from OAuth flows as it doesn't redirect to an external URL
	// Instead, it returns challenge data that the client will use with the WebAuthn API

	// For a basic implementation, create a simple session
	// In a real implementation, you would either:
	// 1. Call BeginLogin for existing users with credentials
	// 2. Call BeginRegistration for new users
	session := &Session{
		Challenge:   state + "_challenge", // Simple challenge generation for demo
		UserID:      state,
		SessionData: nil, // Would be populated in real implementation
		Options:     nil, // Would contain WebAuthn options in real implementation
	}

	return session, nil
}

// FetchUser will process the WebAuthn authentication response and return user information.
func (p *Provider) FetchUser(session social.Session) (social.User, error) {
	sess := session.(*Session)
	user := social.User{
		Provider: p.Name(),
	}

	if sess.UserID == "" {
		return user, fmt.Errorf("%s cannot get user information without user ID", p.providerName)
	}

	// In a real implementation, you would:
	// 1. Verify the WebAuthn assertion response
	// 2. Look up the user from your database based on the credential
	// 3. Return the user information

	// For now, we'll create a basic user structure
	user.UserID = sess.UserID
	user.Name = sess.UserName
	user.Email = sess.UserEmail
	user.Provider = p.Name()

	// Store the raw WebAuthn data
	user.RawData = make(map[string]any)
	user.RawData["challenge"] = sess.Challenge
	user.RawData["user_id"] = sess.UserID
	user.RawData["credential_id"] = sess.CredentialID

	return user, nil
}

// RefreshToken is not applicable for WebAuthn/Passkey authentication
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	return nil, fmt.Errorf("refresh token is not supported by passkey authentication")
}

// RefreshTokenAvailable returns false as passkeys don't use refresh tokens
func (p *Provider) RefreshTokenAvailable() bool {
	return false
}

// BeginRegistration starts the passkey registration process
func (p *Provider) BeginRegistration(userID, userName, userDisplayName string) (interface{}, *webauthn.SessionData, error) {
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
	credential, err := p.webAuthn.FinishRegistration(user, sessionData, response)
	if err != nil {
		return nil, fmt.Errorf("failed to finish WebAuthn registration: %w", err)
	}

	return credential, nil
}

// FinishLogin completes the passkey authentication process
func (p *Provider) FinishLogin(user *WebAuthnUser, sessionData webauthn.SessionData, response *http.Request) (*webauthn.Credential, error) {
	credential, err := p.webAuthn.FinishLogin(user, sessionData, response)
	if err != nil {
		return nil, fmt.Errorf("failed to finish WebAuthn login: %w", err)
	}

	return credential, nil
}
