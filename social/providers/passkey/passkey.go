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

// RegistrationRequest represents the request for beginning registration
type RegistrationRequest struct {
	UserID      string `json:"user_id"`
	UserName    string `json:"user_name"`
	DisplayName string `json:"display_name"`
	Email       string `json:"email,omitempty"`
}

// RegistrationResponse represents the response for beginning registration
type RegistrationResponse struct {
	Options   interface{} `json:"options"`
	SessionID string      `json:"session_id"`
	Challenge string      `json:"challenge"`
	UserID    string      `json:"user_id"`
	Success   bool        `json:"success"`
	Message   string      `json:"message,omitempty"`
}

// FinishRegistrationRequest represents the request for finishing registration
type FinishRegistrationRequest struct {
	SessionID  string      `json:"session_id"`
	UserID     string      `json:"user_id"`
	Credential interface{} `json:"credential"`
}

// FinishRegistrationResponse represents the response for finishing registration
type FinishRegistrationResponse struct {
	Success    bool                 `json:"success"`
	Message    string               `json:"message,omitempty"`
	Credential *webauthn.Credential `json:"credential,omitempty"`
	User       *social.User         `json:"user,omitempty"`
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

// BeginRegistrationEndpoint handles the begin-registration HTTP endpoint
func (p *Provider) BeginRegistrationEndpoint(req *RegistrationRequest) (*RegistrationResponse, error) {
	if req.UserID == "" || req.UserName == "" || req.DisplayName == "" {
		return &RegistrationResponse{
			Success: false,
			Message: "user_id, user_name, and display_name are required",
		}, fmt.Errorf("missing required fields")
	}

	// Create WebAuthn user
	user := &WebAuthnUser{
		ID:          []byte(req.UserID),
		Name:        req.UserName,
		DisplayName: req.DisplayName,
		Credentials: []webauthn.Credential{}, // New user has no credentials
	}

	var options interface{}
	var sessionData *webauthn.SessionData
	var err error

	// If WebAuthn is initialized, use it; otherwise create a mock response
	if p.webAuthn != nil {
		options, sessionData, err = p.webAuthn.BeginRegistration(user)
		if err != nil {
			return &RegistrationResponse{
				Success: false,
				Message: "Failed to begin WebAuthn registration",
			}, fmt.Errorf("failed to begin WebAuthn registration: %w", err)
		}
	} else {
		// Mock response for testing/demo purposes
		options = map[string]interface{}{
			"challenge": req.UserID + "_registration_challenge",
			"rp": map[string]interface{}{
				"name": "FiberAuth",
				"id":   p.RelyingParty,
			},
			"user": map[string]interface{}{
				"id":          req.UserID,
				"name":        req.UserName,
				"displayName": req.DisplayName,
			},
			"pubKeyCredParams": []map[string]interface{}{
				{"type": "public-key", "alg": -7},   // ES256
				{"type": "public-key", "alg": -257}, // RS256
			},
			"timeout": 60000,
		}
	}

	// Generate session ID for tracking this registration
	sessionID := req.UserID + "_reg_" + fmt.Sprintf("%d", len(req.UserID))
	challenge := req.UserID + "_registration_challenge"

	// Store session data if available (in real implementation, you'd store this in a session store)
	if sessionData != nil {
		challenge = string(sessionData.Challenge)
	}

	return &RegistrationResponse{
		Options:   options,
		SessionID: sessionID,
		Challenge: challenge,
		UserID:    req.UserID,
		Success:   true,
		Message:   "Registration challenge generated successfully",
	}, nil
}

// FinishRegistrationEndpoint handles the finish-registration HTTP endpoint
func (p *Provider) FinishRegistrationEndpoint(req *FinishRegistrationRequest) (*FinishRegistrationResponse, error) {
	if req.SessionID == "" || req.UserID == "" || req.Credential == nil {
		return &FinishRegistrationResponse{
			Success: false,
			Message: "session_id, user_id, and credential are required",
		}, fmt.Errorf("missing required fields")
	}

	// In a real implementation, you would:
	// 1. Retrieve the session data using the session_id
	// 2. Verify the credential response using WebAuthn
	// 3. Store the credential in your database
	// 4. Create a user account if it doesn't exist

	var credential *webauthn.Credential

	if p.webAuthn != nil {
		// For a real implementation, you'd need to:
		// - Retrieve stored session data
		// - Parse the credential response
		// - Verify it with WebAuthn

		// Mock successful registration for now
		credential = &webauthn.Credential{
			ID:              []byte("mock_credential_id"),
			PublicKey:       []byte("mock_public_key"),
			AttestationType: "none",
		}
	} else {
		// Mock credential for testing
		credential = &webauthn.Credential{
			ID:              []byte("mock_credential_id"),
			PublicKey:       []byte("mock_public_key"),
			AttestationType: "none",
		}
	}

	// Create user object
	user := &social.User{
		UserID:   req.UserID,
		Provider: p.Name(),
		RawData:  make(map[string]any),
	}

	// Store credential information in raw data
	user.RawData["credential_id"] = string(credential.ID)
	user.RawData["registration_complete"] = true
	user.RawData["session_id"] = req.SessionID

	return &FinishRegistrationResponse{
		Success:    true,
		Message:    "Registration completed successfully",
		Credential: credential,
		User:       user,
	}, nil
}

// BeginLoginEndpoint handles the begin-login HTTP endpoint for existing users
func (p *Provider) BeginLoginEndpoint(userID string) (*RegistrationResponse, error) {
	if userID == "" {
		return &RegistrationResponse{
			Success: false,
			Message: "user_id is required",
		}, fmt.Errorf("user_id is required")
	}

	// In a real implementation, you would:
	// 1. Look up the user's credentials from your database
	// 2. Create a WebAuthn assertion request

	var options interface{}
	var err error

	if p.webAuthn != nil {
		// Mock user with existing credentials (in real implementation, load from DB)
		user := &WebAuthnUser{
			ID:          []byte(userID),
			Name:        "user", // Would be loaded from DB
			DisplayName: "User", // Would be loaded from DB
			Credentials: []webauthn.Credential{
				{
					ID:        []byte("existing_credential_id"),
					PublicKey: []byte("existing_public_key"),
				},
			},
		}

		options, _, err = p.webAuthn.BeginLogin(user)
		if err != nil {
			return &RegistrationResponse{
				Success: false,
				Message: "Failed to begin WebAuthn login",
			}, fmt.Errorf("failed to begin WebAuthn login: %w", err)
		}
	} else {
		// Mock response for testing
		options = map[string]interface{}{
			"challenge": userID + "_login_challenge",
			"rpId":      p.RelyingParty,
			"allowCredentials": []map[string]interface{}{
				{
					"type": "public-key",
					"id":   userID + "_credential",
				},
			},
			"timeout": 60000,
		}
	}

	sessionID := userID + "_login_" + fmt.Sprintf("%d", len(userID))
	challenge := userID + "_login_challenge"

	return &RegistrationResponse{
		Options:   options,
		SessionID: sessionID,
		Challenge: challenge,
		UserID:    userID,
		Success:   true,
		Message:   "Login challenge generated successfully",
	}, nil
}
