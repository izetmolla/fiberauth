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

	provider, err := passkeyProvider()
	a.NoError(err)

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
}

func Test_Session_Authorize_MissingUserID(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider, err := passkeyProvider()
	a.NoError(err)

	session := &passkey.Session{
		Challenge: "test_challenge",
	}

	params := &MockParams{
		values: map[string]string{},
	}

	_, err = session.Authorize(provider, params)
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
	}

	marshaled := session.Marshal()
	a.Contains(marshaled, "test_challenge")
	a.Contains(marshaled, "test_user")
	a.Contains(marshaled, "Test User")
	a.Contains(marshaled, "test@example.com")
	a.Contains(marshaled, "test_credential")
}

func Test_Session_String(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	session := &passkey.Session{
		Challenge: "test_challenge",
		UserID:    "test_user",
	}

	str := session.String()
	marshaled := session.Marshal()
	a.Equal(marshaled, str)
}

// MockParams implements social.Params for testing
type MockParams struct {
	values map[string]string
}

func (m *MockParams) Get(key string) string {
	return m.values[key]
}
