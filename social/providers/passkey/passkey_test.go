package passkey_test

import (
	"testing"

	"github.com/izetmolla/fiberauth/social"
	"github.com/izetmolla/fiberauth/social/providers/passkey"
	"github.com/stretchr/testify/assert"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider, err := passkeyProvider()
	a.NoError(err)
	a.Equal(provider.Name(), "passkey")
	a.Equal("/callback", provider.CallbackURL)
}

func Test_Implements_Provider(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider, err := passkeyProvider()
	a.NoError(err)
	a.Implements((*social.Provider)(nil), provider)
}

func Test_BeginAuth(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider, err := passkeyProvider()
	a.NoError(err)

	session, err := provider.BeginAuth("test_state")
	a.NoError(err)

	s := session.(*passkey.Session)
	a.Equal("test_state", s.UserID)
	a.Equal("test_state_challenge", s.Challenge)
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider, err := passkeyProvider()
	a.NoError(err)

	sessionJSON := `{"challenge":"test_challenge","user_id":"test_user","user_name":"Test User","user_email":"test@example.com","credential_id":"test_credential"}`
	s, err := provider.UnmarshalSession(sessionJSON)
	a.NoError(err)

	session := s.(*passkey.Session)
	a.Equal("test_challenge", session.Challenge)
	a.Equal("test_user", session.UserID)
	a.Equal("Test User", session.UserName)
	a.Equal("test@example.com", session.UserEmail)
	a.Equal("test_credential", session.CredentialID)
}

func Test_RefreshTokenAvailable(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider, err := passkeyProvider()
	a.NoError(err)
	a.False(provider.RefreshTokenAvailable())
}

func Test_RefreshToken(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider, err := passkeyProvider()
	a.NoError(err)

	_, err = provider.RefreshToken("test_token")
	a.Error(err)
	a.Contains(err.Error(), "refresh token is not supported")
}

func Test_SetName(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider, err := passkeyProvider()
	a.NoError(err)

	provider.SetName("custom_passkey")
	a.Equal("custom_passkey", provider.Name())
}

func passkeyProvider() (*passkey.Provider, error) {
	return passkey.New("localhost", "http://localhost:3000", "/callback")
}
