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

	provider := passkeyProvider()
	a.Equal(provider.Name(), "passkey")
	a.Equal("/callback", provider.CallbackURL)
	a.Equal("localhost", provider.RelyingParty)
	a.Equal("http://localhost:3000", provider.Origin)
}

func Test_Implements_Provider(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := passkeyProvider()
	a.Implements((*social.Provider)(nil), provider)
}

func Test_BeginAuth(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := passkeyProvider()

	session, err := provider.BeginAuth("test_state")
	a.NoError(err)

	s := session.(*passkey.Session)
	a.Equal("test_state", s.UserID)
	a.Equal("test_state_challenge", s.Challenge)
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := passkeyProvider()

	sessionJSON := `{"challenge":"test_challenge","user_id":"test_user","user_name":"Test User","user_email":"test@example.com","credential_id":"test_credential","access_token":"test_token"}`
	s, err := provider.UnmarshalSession(sessionJSON)
	a.NoError(err)

	session := s.(*passkey.Session)
	a.Equal("test_challenge", session.Challenge)
	a.Equal("test_user", session.UserID)
	a.Equal("Test User", session.UserName)
	a.Equal("test@example.com", session.UserEmail)
	a.Equal("test_credential", session.CredentialID)
	a.Equal("test_token", session.AccessToken)
}

func Test_RefreshTokenAvailable(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := passkeyProvider()
	a.False(provider.RefreshTokenAvailable())
}

func Test_RefreshToken(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := passkeyProvider()

	_, err := provider.RefreshToken("test_token")
	a.Error(err)
	a.Contains(err.Error(), "refresh token is not supported")
}

func Test_SetName(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := passkeyProvider()

	provider.SetName("custom_passkey")
	a.Equal("custom_passkey", provider.Name())
}

func Test_SetRelyingParty(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := passkeyProvider()

	provider.SetRelyingParty("example.com")
	a.Equal("example.com", provider.RelyingParty)
}

func Test_SetOrigin(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := passkeyProvider()

	provider.SetOrigin("https://example.com")
	a.Equal("https://example.com", provider.Origin)
}

func passkeyProvider() *passkey.Provider {
	return passkey.New("localhost", "http://localhost:3000", "/callback")
}
