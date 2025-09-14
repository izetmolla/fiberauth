package passkey_test

import (
	"testing"

	"github.com/izetmolla/fiberauth/social/providers/passkey"
	"github.com/stretchr/testify/assert"
)

func Test_Session_GetAuthURL(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	session := &passkey.Session{
		Challenge: "test_challenge",
		UserID:    "test_user",
	}

	authURL, err := session.GetAuthURL()
	a.NoError(err)
	a.Equal("test_challenge", authURL)
}

func Test_Session_GetAuthURL_EmptyChallenge(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	session := &passkey.Session{}

	_, err := session.GetAuthURL()
	a.Error(err)
	a.Contains(err.Error(), "an AuthURL has not been set")
}

func Test_Session_Authorize(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := passkeyProvider()

	session := &passkey.Session{
		Challenge: "test_challenge",
	}

	params := &MockParams{
		values: map[string]string{
			"user_id":       "test_user_123",
			"user_name":     "Test User",
			"user_email":    "test@example.com",
			"credential_id": "test_credential_456",
		},
	}

	token, err := session.Authorize(provider, params)
	a.NoError(err)
	a.Equal("test_user_123", token)
	a.Equal("test_user_123", session.UserID)
	a.Equal("Test User", session.UserName)
	a.Equal("test@example.com", session.UserEmail)
	a.Equal("test_credential_456", session.CredentialID)
	a.Equal("test_user_123", session.AccessToken)
}

func Test_Session_Authorize_MissingUserID(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := passkeyProvider()

	session := &passkey.Session{
		Challenge: "test_challenge",
	}

	params := &MockParams{
		values: map[string]string{},
	}

	_, err := session.Authorize(provider, params)
	a.Error(err)
	a.Contains(err.Error(), "user_id is required")
}

func Test_Session_Marshal(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	session := &passkey.Session{
		Challenge:    "test_challenge",
		UserID:       "test_user",
		UserName:     "Test User",
		UserEmail:    "test@example.com",
		CredentialID: "test_credential",
		AccessToken:  "test_token",
	}

	marshaled := session.Marshal()
	a.Contains(marshaled, "test_challenge")
	a.Contains(marshaled, "test_user")
	a.Contains(marshaled, "Test User")
	a.Contains(marshaled, "test@example.com")
	a.Contains(marshaled, "test_credential")
	a.Contains(marshaled, "test_token")
}

func Test_Session_String(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	session := &passkey.Session{
		Challenge:   "test_challenge",
		UserID:      "test_user",
		AccessToken: "test_token",
	}

	str := session.String()
	marshaled := session.Marshal()
	a.Equal(marshaled, str)
	a.Contains(marshaled, "test_challenge")
	a.Contains(marshaled, "test_token")
}

func Test_FetchUser(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := passkeyProvider()

	session := &passkey.Session{
		Challenge:    "test_challenge",
		UserID:       "test_user_123",
		UserName:     "Test User",
		UserEmail:    "test@example.com",
		CredentialID: "test_credential_456",
		AccessToken:  "test_token",
	}

	user, err := provider.FetchUser(session)
	a.NoError(err)
	a.Equal("test_user_123", user.UserID)
	a.Equal("Test User", user.Name)
	a.Equal("test@example.com", user.Email)
	a.Equal("passkey", user.Provider)
	a.Equal("test_token", user.AccessToken)

	// Check raw data
	a.NotNil(user.RawData)
	a.Equal("test_challenge", user.RawData["challenge"])
	a.Equal("test_user_123", user.RawData["user_id"])
	a.Equal("test_credential_456", user.RawData["credential_id"])
}

func Test_FetchUser_EmptyUserID(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := passkeyProvider()

	session := &passkey.Session{
		Challenge:   "test_challenge",
		AccessToken: "test_token",
	}

	_, err := provider.FetchUser(session)
	a.Error(err)
	a.Contains(err.Error(), "cannot get user information without user ID")
}

// MockParams implements social.Params for testing
type MockParams struct {
	values map[string]string
}

func (m *MockParams) Get(key string) string {
	return m.values[key]
}
