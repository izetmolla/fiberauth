package passkey

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/izetmolla/fiberauth/social"
)

// Session stores data during the WebAuthn authentication process.
type Session struct {
	Challenge    string                `json:"challenge"`
	UserID       string                `json:"user_id"`
	UserName     string                `json:"user_name"`
	UserEmail    string                `json:"user_email"`
	CredentialID string                `json:"credential_id"`
	AccessToken  string                `json:"access_token"`
	SessionData  *webauthn.SessionData `json:"session_data"`
	Options      interface{}           `json:"options"`
}

// GetAuthURL returns a JSON representation of the WebAuthn options instead of a URL.
// For WebAuthn, we don't redirect to an external URL, but rather return challenge data
// that the client-side JavaScript will use with the WebAuthn API.
func (s Session) GetAuthURL() (string, error) {
	if s.Challenge == "" {
		return "", errors.New(social.NoAuthUrlErrorMessage)
	}

	// Return the WebAuthn options as JSON string
	// The client will use this data to call navigator.credentials.get()
	if s.Options != nil {
		optionsJSON, err := json.Marshal(s.Options)
		if err != nil {
			return "", err
		}
		return string(optionsJSON), nil
	}

	return s.Challenge, nil
}

// Authorize processes the WebAuthn authentication response.
// For WebAuthn, params should contain the WebAuthn assertion response.
func (s *Session) Authorize(provider social.Provider, params social.Params) (string, error) {
	_ = provider.(*Provider)

	// In a real implementation, you would:
	// 1. Parse the WebAuthn assertion response from params
	// 2. Verify the assertion using p.webAuthn.FinishLogin()
	// 3. Update the session with the authenticated user information

	// For now, we'll simulate a successful authentication
	userID := params.Get("user_id")
	if userID == "" {
		return "", errors.New("user_id is required for passkey authentication")
	}

	userName := params.Get("user_name")
	userEmail := params.Get("user_email")
	credentialID := params.Get("credential_id")

	s.UserID = userID
	s.UserName = userName
	s.UserEmail = userEmail
	s.CredentialID = credentialID
	s.AccessToken = userID // Use userID as access token for demo

	// Return a token-like identifier (in real implementation, this might be a JWT or session ID)
	return s.AccessToken, nil
}

// Marshal the session into a string
func (s Session) Marshal() string {
	b, _ := json.Marshal(s)
	return string(b)
}

func (s Session) String() string {
	return s.Marshal()
}

// UnmarshalSession will unmarshal a JSON string into a session.
func (p *Provider) UnmarshalSession(data string) (social.Session, error) {
	sess := &Session{}
	err := json.NewDecoder(strings.NewReader(data)).Decode(sess)
	return sess, err
}
